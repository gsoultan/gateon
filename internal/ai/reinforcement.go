// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	lru "github.com/hashicorp/golang-lru"
)

// IPState holds the reinforcement learning state for one kernel limit entry:
// an IPv4 address, or an IPv6 /64 (ebpf.LimitKey).
type IPState struct {
	mu           sync.Mutex
	QValue       float64
	LastFeedback time.Time
	// limited records whether an eBPF adaptive limit is currently installed for
	// this IP, so the limit is cleared exactly once when the score decays
	// instead of on every subsequent low-score observation.
	limited bool
}

// qValueDecayHalfLife is how long an idle IP takes to shed half its threat
// score.
//
// The Q-value only ever moved when new feedback arrived. An IP that tripped the
// limiter and then went quiet — which is exactly what a scanner does after
// being throttled, and also what a false-positive NAT gateway does when its
// users give up — kept its score forever and stayed throttled forever. Decaying
// against wall-clock time on read means quiet is a path back.
const qValueDecayHalfLife = 10 * time.Minute

// idleStateTTL is how long an IP's state survives with no feedback before it is
// eligible for eviction. Well past the point its score has decayed to noise.
const idleStateTTL = time.Hour

// The limits, as the minimum spacing the kernel enforces between an address's
// packets. The kernel's token bucket earns one packet per interval (after a
// 64-packet burst), so a LONGER interval is a TIGHTER limit.
const (
	intervalModerate = 10 * time.Millisecond  // 100 packets a second
	intervalHigh     = 50 * time.Millisecond  // 20
	intervalCritical = 200 * time.Millisecond // 5
)

// ReinforcementLearningLimiter turns repeated high-confidence findings into
// adaptive kernel rate limits, and lets them go again.
//
// Each observation moves an address's score a fifth of the way towards the
// finding's confidence, and the score halves every qValueDecayHalfLife without
// one. From zero, no single finding -- nor two -- reaches the first limit: an
// address is limited only after findings on repeated analysis passes, and the
// limit is set again on each, which renews its lease (ebpf.AdaptiveLimitLease)
// for as long as the findings last. The mitigation allowlist is never limited,
// and Forget -- an operator's release -- clears both the limit and the history.
//
// The state map is an LRU with a hard capacity rather than an unbounded
// sync.Map. Its keys are remote addresses chosen by whoever is sending traffic,
// and they are the kernel's keys (ebpf.LimitKey): an IPv6 /64 is one entry,
// however many addresses a host walks through in it.
type ReinforcementLearningLimiter struct {
	ebpf   ebpf.Manager
	states *lru.Cache
	now    func() time.Time // injectable for tests
}

// NewReinforcementLearningLimiter creates a new RL-based rate limiter.
func NewReinforcementLearningLimiter(ebpfMgr ebpf.Manager) *ReinforcementLearningLimiter {
	capacity := config.CurrentTierDefaults().RLLimiterStates
	cache, err := lru.NewWithEvict(capacity, func(key, value any) {
		// An evicted IP loses its Go-side state, so nothing here would clear
		// its kernel-side limit again. It is not stranded: the Holder leased it
		// (ebpf.AdaptiveLimitLease), and with nobody renewing it, it lapses.
		ip, _ := key.(string)
		st, _ := value.(*IPState)
		if ip == "" || st == nil {
			return
		}
		if st.isLimited() {
			logger.L.LogDebug("evicting rate-limit state; its kernel limit lapses with its lease", "ip", ip)
		}
	})
	if err != nil {
		// Only returned for a non-positive size; fall back to the standard tier.
		cache, _ = lru.New(config.DefaultsFor(config.TierStandard).RLLimiterStates)
	}

	return &ReinforcementLearningLimiter{
		ebpf:   ebpfMgr,
		states: cache,
		now:    time.Now,
	}
}

// isLimited reports whether the state has a kernel limit installed.
func (st *IPState) isLimited() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.limited
}

// ProcessFeedback records one observation of ip at confidence score (0 to 1)
// -- one per analysis pass: callers aggregate a pass's findings first -- and
// sets, renews or lifts the address's kernel limit accordingly.
func (rl *ReinforcementLearningLimiter) ProcessFeedback(ip string, score float64) {
	key, ok := ebpf.LimitKey(ip)
	if !ok || rl.states == nil {
		return
	}
	// The operator's allowlist is never limited, whatever the evidence; and an
	// address allowlisted after it was limited is released on its next finding.
	if mitigation.IsAllowlisted(ip) {
		rl.Forget(key)
		return
	}

	now := rl.now()
	state := rl.state(key, now)
	state.mu.Lock()

	// Decay first, so the update is applied to a score that reflects how long
	// this IP has been quiet rather than to a stale peak.
	state.QValue = decayQValue(state.QValue, now.Sub(state.LastFeedback))

	// Q-Learning update rule (simplified): Q(s) = Q(s) + alpha * (reward - Q(s))
	const alpha = 0.2
	state.QValue += alpha * (score - state.QValue)
	state.LastFeedback = now

	q := state.QValue
	wasLimited := state.limited
	interval := adaptiveInterval(q)
	state.limited = interval > 0
	state.mu.Unlock()

	rl.applyAdaptiveLimit(key, interval, wasLimited)
}

// state is key's state, created on first sight.
//
// LoadOrStore semantics, not Load-then-Store. Two goroutines reporting the same
// IP concurrently used to each build their own IPState, lock their own mutex and
// race to Store; one update was silently lost and the winner's state was not
// necessarily the one left in the map. The race detector could not see it
// because each goroutine held a different lock.
func (rl *ReinforcementLearningLimiter) state(key string, now time.Time) *IPState {
	if v, ok := rl.states.Get(key); ok {
		if s, isState := v.(*IPState); isState && s != nil {
			return s
		}
	}
	state := &IPState{LastFeedback: now}
	if prev, existed, _ := rl.states.PeekOrAdd(key, state); existed {
		if s, isState := prev.(*IPState); isState && s != nil {
			return s
		}
	}
	return state
}

// Forget drops ip's state -- its kernel entry's, so for IPv6 its /64's -- and
// lifts the limit it installed. An operator who releases an address is saying
// the findings against it were wrong; a history kept through that release would
// limit it again on the very next pass. Findings made after it start from zero,
// and need repeated passes again before anything is limited.
func (rl *ReinforcementLearningLimiter) Forget(ip string) {
	key, ok := ebpf.LimitKey(ip)
	if !ok || rl.states == nil {
		return
	}
	v, found := rl.states.Peek(key)
	if !found {
		return
	}
	rl.states.Remove(key)
	if st, isState := v.(*IPState); isState && st != nil && st.isLimited() {
		rl.applyAdaptiveLimit(key, 0, true)
	}
}

// decayQValue applies exponential decay with qValueDecayHalfLife.
func decayQValue(q float64, elapsed time.Duration) float64 {
	if q <= 0 || elapsed <= 0 {
		return q
	}
	halfLives := elapsed.Seconds() / qValueDecayHalfLife.Seconds()
	// Cheap equivalent of q * 2^-halfLives without pulling in math.Exp for the
	// common case of a small number of half-lives.
	for range int(halfLives) {
		q /= 2
		if q < 1e-4 {
			return 0
		}
	}
	if frac := halfLives - float64(int(halfLives)); frac > 0 {
		q *= 1 - frac/2
	}
	return q
}

// adaptiveInterval maps a threat score to the address's limit. Zero means "no
// limit", which is a state that must be applied, not skipped.
//
// The table used to run the other way -- 10ms for the most dangerous addresses,
// 200ms for the least -- on the belief that a shorter interval was the harsher
// limit. The kernel earns one packet per interval, so it gave a score above 0.9
// twenty times the packets of a score above 0.4.
func adaptiveInterval(qValue float64) time.Duration {
	switch {
	case qValue > 0.9:
		return intervalCritical
	case qValue > 0.7:
		return intervalHigh
	case qValue > 0.4:
		return intervalModerate
	default:
		return 0
	}
}

// applyAdaptiveLimit pushes the decision to eBPF.
//
// The previous version computed interval == 0 for a decayed score and then
// skipped the call entirely, so a throttle could be installed but never
// removed: the comment said "or clear it" and the code did not. An IP
// throttled once stayed throttled for the life of the process even after its
// score fell to zero.
func (rl *ReinforcementLearningLimiter) applyAdaptiveLimit(ip string, interval time.Duration, wasLimited bool) {
	if rl.ebpf == nil {
		return
	}

	if interval > 0 {
		if err := rl.ebpf.SetAdaptiveRateLimit(ip, interval); err != nil {
			logger.L.LogWarn("failed to set adaptive rate limit", "ip", ip, "error", err)
		}
		return
	}

	// Only clear a limit we actually installed, so a decayed-but-never-limited
	// IP does not generate a map delete on every observation.
	if wasLimited {
		if err := rl.ebpf.ClearAdaptiveRateLimit(ip); err != nil {
			logger.L.LogWarn("failed to clear adaptive rate limit", "ip", ip, "error", err)
		}
	}
}

// Sweep drops states that have seen no feedback within idleStateTTL, releasing
// any kernel limit they still hold. The LRU bounds memory on its own; this
// returns capacity and kernel map slots proactively rather than waiting for
// pressure to evict entries that are already irrelevant.
func (rl *ReinforcementLearningLimiter) Sweep() {
	if rl.states == nil {
		return
	}
	cutoff := rl.now().Add(-idleStateTTL)
	for _, key := range rl.states.Keys() {
		ip, ok := key.(string)
		if !ok {
			continue
		}
		v, ok := rl.states.Peek(ip)
		if !ok {
			continue
		}
		st, ok := v.(*IPState)
		if !ok || st == nil {
			rl.states.Remove(ip)
			continue
		}
		st.mu.Lock()
		idle := st.LastFeedback.Before(cutoff)
		limited := st.limited
		st.mu.Unlock()
		if !idle {
			continue
		}
		if limited && rl.ebpf != nil {
			if err := rl.ebpf.ClearAdaptiveRateLimit(ip); err != nil {
				logger.L.LogWarn("failed to clear adaptive rate limit during sweep", "ip", ip, "error", err)
			}
		}
		rl.states.Remove(ip)
	}
}

// Len reports how many IP states are currently tracked.
func (rl *ReinforcementLearningLimiter) Len() int {
	if rl.states == nil {
		return 0
	}
	return rl.states.Len()
}
