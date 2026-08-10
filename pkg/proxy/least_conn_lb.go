// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// LeastConnLB implements least connections load balancing.
type LeastConnLB struct {
	targetsPtr atomic.Pointer[[]*targetState]
	mu         sync.Mutex
}

func NewLeastConnLB(urls []string) *LeastConnLB {
	targets := make([]*targetState, len(urls))
	for i, u := range urls {
		targets[i] = newTargetState(u, 1)
	}
	lb := &LeastConnLB{}
	lb.targetsPtr.Store(&targets)
	return lb
}

func (lb *LeastConnLB) Next() string {
	s := lb.NextState()
	if s == nil {
		return ""
	}
	return s.url
}

func (lb *LeastConnLB) NextState() *targetState {
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return nil
	}
	targets := *ptr
	if len(targets) == 0 {
		return nil
	}
	var best *targetState
	for _, t := range targets {
		if !t.alive.Load() {
			continue
		}
		if best == nil || atomic.LoadInt32(&t.activeConn) < atomic.LoadInt32(&best.activeConn) {
			best = t
		}
	}
	return best
}

func (lb *LeastConnLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	newTargets := make([]*targetState, len(targets))
	for i, t := range targets {
		newTargets[i] = newTargetStateFromTarget(t)
	}
	lb.targetsPtr.Store(&newTargets)
}

func (lb *LeastConnLB) SetAlive(url string, alive bool) {
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

func (lb *LeastConnLB) GetStats() []TargetStats {
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

func (lb *LeastConnLB) RecordLatency(url string, latency float64) {
	// LeastConnLB doesn't use latency for balancing.
}
