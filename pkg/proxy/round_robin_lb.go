// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RoundRobinLB rotates through its targets in proportion to their weights.
//
// It ignored weights, and round robin is the default policy, so the Weight the
// service form shows on every target ("Higher weight = more traffic") was saved
// and did nothing: weights 1:2:6 gave 30/30/30 (ADR 0047). Equal weights --
// what the form saves unless someone changes one -- are plain rotation, as
// before. Weighted round robin is the same balancer (WeightedRoundRobinLB).
//
// The pick is one atomic increment and one slice index while the target it
// lands on is alive. The smooth order is computed when the targets change, on
// the configuration path, never per request.
type RoundRobinLB struct {
	set     atomic.Pointer[rrSet]
	current uint64
	// skipped counts the turns that fell on a dead target, and spreads them
	// over the live ones in their own rotation.
	skipped uint64
	mu      sync.Mutex
}

// rrSet is one target list and the order it is served in, swapped together so
// a pick never indexes one list with the other's order.
type rrSet struct {
	targets []*targetState
	// shares are the targets' effective weights: their own when any target
	// carries one, and 1 each when none does.
	shares []int32
	// order is the smooth weighted schedule, nil when it would be longer than
	// maxScheduleLen; picks then walk the shares instead.
	order []uint32
}

func NewRoundRobinLB(urls []string) *RoundRobinLB {
	targets := make([]*gateonv1.Target, len(urls))
	for i, u := range urls {
		targets[i] = &gateonv1.Target{Url: u, Weight: 1}
	}
	lb := &RoundRobinLB{}
	lb.UpdateWeightedTargets(targets)
	return lb
}

func (lb *RoundRobinLB) Next() string {
	s := lb.NextState()
	if s == nil {
		return ""
	}
	return s.url
}

func (lb *RoundRobinLB) NextState() *targetState {
	set := lb.set.Load()
	if set == nil || len(set.targets) == 0 {
		return nil
	}
	n := atomic.AddUint64(&lb.current, 1) - 1
	if len(set.order) == 0 {
		return set.pickLive(n)
	}
	if t := set.targets[set.order[n%uint64(len(set.order))]]; t.alive.Load() {
		return t
	}
	return set.pickLive(atomic.AddUint64(&lb.skipped, 1) - 1)
}

// pickLive returns the live target that turn k lands on when turns are dealt
// over the live targets in proportion to their shares.
//
// It used to scan forward to the next live target, which gave a dead target's
// whole share to its neighbour: one of three down left the next one serving
// twice what the other did. Nil when no target with a share is alive.
func (s *rrSet) pickLive(k uint64) *targetState {
	var total uint64
	for i, t := range s.targets {
		if s.shares[i] > 0 && t.alive.Load() {
			total += uint64(s.shares[i])
		}
	}
	if total == 0 {
		return nil
	}
	k %= total
	for i, t := range s.targets {
		if s.shares[i] <= 0 || !t.alive.Load() {
			continue
		}
		if k < uint64(s.shares[i]) {
			return t
		}
		k -= uint64(s.shares[i])
	}
	return nil // a target died between the sum and the walk
}

func (lb *RoundRobinLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	states := make([]*targetState, len(targets))
	for i, t := range targets {
		states[i] = newTargetStateFromTarget(t)
	}
	shares := effectiveShares(targets)
	lb.set.Store(&rrSet{targets: states, shares: shares, order: smoothSchedule(shares)})
}

func (lb *RoundRobinLB) SetAlive(url string, alive bool) {
	set := lb.set.Load()
	if set == nil {
		return
	}
	for _, t := range set.targets {
		if t.url == url {
			if t.alive.Load() != alive {
				state := telemetry.CircuitClosed
				if !alive {
					state = telemetry.CircuitOpen
				}
				telemetry.RecordCircuitBreakerEvent(url, state, "health check")
			}
			t.alive.Store(alive)
			return
		}
	}
}

func (lb *RoundRobinLB) GetStats() []TargetStats {
	set := lb.set.Load()
	if set == nil {
		return nil
	}
	stats := make([]TargetStats, len(set.targets))
	for i, t := range set.targets {
		stats[i] = targetStatsFromState(t)
	}
	return stats
}

func (lb *RoundRobinLB) RecordLatency(url string, latency float64) {
	// Round robin does not use latency for balancing.
}
