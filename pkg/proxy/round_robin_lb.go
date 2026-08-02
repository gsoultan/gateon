// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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
	mu         sync.Mutex
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
	// Round-robin among alive targets only (circuit breaker: skip OPEN targets)
	n := atomic.AddUint64(&lb.current, 1)
	start := (n - 1) % uint64(len(targets))
	for i := uint64(0); i < uint64(len(targets)); i++ {
		idx := (start + i) % uint64(len(targets))
		t := targets[idx]
		if t.alive.Load() {
			return t
		}
	}
	return nil // no alive targets
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
