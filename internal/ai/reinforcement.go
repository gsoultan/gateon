// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package ai

import (
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	lru "github.com/hashicorp/golang-lru"
)

// IPState holds the reinforcement learning state for a specific IP address.
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

// ReinforcementLearningLimiter implements RL logic for adaptive rate limiting.
// It learns from security feedback to dynamically adjust eBPF rate limits.
//
// The state map is an LRU with a hard capacity rather than an unbounded
// sync.Map. Its keys are remote IP addresses supplied by the eBPF feedback
// path, i.e. chosen by whoever is sending traffic: a single host walking an
// IPv6 /64 can mint effectively unlimited distinct keys. Unbounded, that is a
// memory-exhaustion path on a machine whose whole budget is a couple of
// gigabytes, and it is reachable by anyone who can send packets.
type ReinforcementLearningLimiter struct {
	ebpf   ebpf.Manager
	states *lru.Cache
	now    func() time.Time // injectable for tests
}

// NewReinforcementLearningLimiter creates a new RL-based rate limiter.
func NewReinforcementLearningLimiter(ebpfMgr ebpf.Manager) *ReinforcementLearningLimiter {
	capacity := config.CurrentTierDefaults().RLLimiterStates
	cache, err := lru.NewWithEvict(capacity, func(key, value any) {
		// An evicted IP loses its Go-side state, so nothing would ever clear
		// its kernel-side limit again. Release it on the way out rather than
		// stranding a throttle with no owner.
		ip, _ := key.(string)
		st, _ := value.(*IPState)
		if ip == "" || st == nil {
			return
		}
		st.mu.Lock()
		limited := st.limited
		st.mu.Unlock()
		if limited {
			logger.L.LogDebug("evicting rate-limit state, releasing kernel limit", "ip", ip)
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

// ProcessFeedback updates the RL model with feedback score (0.0 to 1.0) and
// adjusts rate limits.
func (rl *ReinforcementLearningLimiter) ProcessFeedback(ip string, score float64) {
	if ip == "" || rl.states == nil {
		return
	}

	now := rl.now()

	// LoadOrStore semantics, not Load-then-Store. Two goroutines reporting the
	// same IP concurrently used to each build their own IPState, lock their own
	// mutex and race to Store; one update was silently lost and the winner's
	// state was not necessarily the one left in the map. The race detector
	// could not see it because each goroutine held a different lock.
	var state *IPState
	if v, ok := rl.states.Get(ip); ok {
		state, _ = v.(*IPState)
	}
	if state == nil {
		state = &IPState{LastFeedback: now}
		if prev, existed, _ := rl.states.PeekOrAdd(ip, state); existed {
			if s, ok := prev.(*IPState); ok && s != nil {
				state = s
			}
		}
	}

	state.mu.Lock()

	// Decay first, so the update is applied to a score that reflects how long
	// this IP has been quiet rather than to a stale peak.
	state.QValue = decayQValue(state.QValue, now.Sub(state.LastFeedback))

	// Q-Learning update rule (simplified): Q(s) = Q(s) + alpha * (reward - Q(s))
	// Here, the 'score' from Neural Sentinel acts as the perceived 'threat reward'.
	const alpha = 0.2
	state.QValue += alpha * (score - state.QValue)
	state.LastFeedback = now

	q := state.QValue
	wasLimited := state.limited
	interval := adaptiveInterval(q)
	state.limited = interval > 0
	state.mu.Unlock()

	rl.applyAdaptiveLimit(ip, interval, wasLimited)
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

// adaptiveInterval maps a threat score to a per-IP minimum packet interval.
// Zero means "no limit", which is a state that must be applied, not skipped.
func adaptiveInterval(qValue float64) time.Duration {
	switch {
	case qValue > 0.9:
		// Critical threat: 10ms interval (very aggressive)
		return 10 * time.Millisecond
	case qValue > 0.7:
		// High threat: 50ms interval
		return 50 * time.Millisecond
	case qValue > 0.4:
		// Moderate threat: 200ms interval
		return 200 * time.Millisecond
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
