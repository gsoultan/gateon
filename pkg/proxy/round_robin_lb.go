// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RoundRobinLB implements simple round-robin load balancing.
type RoundRobinLB struct {
	targetsPtr atomic.Pointer[[]*targetState]
	current    uint64
	// skipped counts the turns that fell on a dead target, and spreads them
	// over the live ones in their own rotation.
	skipped uint64
	mu      sync.Mutex
}

func NewRoundRobinLB(urls []string) *RoundRobinLB {
	targets := make([]*targetState, len(urls))
	for i, u := range urls {
		targets[i] = newTargetState(u, 1)
	}
	lb := &RoundRobinLB{}
	lb.targetsPtr.Store(&targets)
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
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return nil
	}
	targets := *ptr

	if len(targets) == 0 {
		return nil
	}
	n := atomic.AddUint64(&lb.current, 1) - 1
	if t := targets[n%uint64(len(targets))]; t.alive.Load() {
		return t
	}
	return lb.nextAliveFor(targets)
}

// nextAliveFor picks a live target for a turn that fell on a dead one. It used
// to scan forward to the next live target, which gave a dead target's whole
// share to its neighbour: one of three down left the next one serving twice
// what the other did, and two of four down left one serving three quarters.
// The skipped turns take their own rotation over the live targets instead.
func (lb *RoundRobinLB) nextAliveFor(targets []*targetState) *targetState {
	alive := 0
	for _, t := range targets {
		if t.alive.Load() {
			alive++
		}
	}
	if alive == 0 {
		return nil
	}
	k := (atomic.AddUint64(&lb.skipped, 1) - 1) % uint64(alive)
	for _, t := range targets {
		if !t.alive.Load() {
			continue
		}
		if k == 0 {
			return t
		}
		k--
	}
	return nil // a target died between the count and the pick
}

func (lb *RoundRobinLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	newTargets := make([]*targetState, len(targets))
	for i, t := range targets {
		newTargets[i] = newTargetStateFromTarget(t)
	}
	lb.targetsPtr.Store(&newTargets)
}

func (lb *RoundRobinLB) SetAlive(url string, alive bool) {
	// alive is atomic in targetState, but we might need to find the target.
	// We don't need a lock to find and update because the slice itself is atomic,
	// and targetState.alive is atomic.
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return
	}
	for _, t := range *ptr {
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
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return nil
	}
	targets := *ptr
	stats := make([]TargetStats, len(targets))
	for i, t := range targets {
		stats[i] = targetStatsFromState(t)
	}
	return stats
}

func (lb *RoundRobinLB) RecordLatency(url string, latency float64) {
	// RoundRobinLB doesn't use latency for balancing.
}
