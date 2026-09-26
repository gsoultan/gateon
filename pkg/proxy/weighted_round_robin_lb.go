// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// WeightedRoundRobinLB implements weighted round-robin load balancing.
type WeightedRoundRobinLB struct {
	targetsPtr atomic.Pointer[[]*targetState]
	current    uint64
	mu         sync.Mutex
}

func NewWeightedRoundRobinLB(targets []*gateonv1.Target) *WeightedRoundRobinLB {
	lbTargets := make([]*targetState, len(targets))
	for i, t := range targets {
		lbTargets[i] = newTargetStateFromTarget(t)
	}
	lb := &WeightedRoundRobinLB{}
	lb.targetsPtr.Store(&lbTargets)
	return lb
}

func (lb *WeightedRoundRobinLB) Next() string {
	s := lb.NextState()
	if s == nil {
		return ""
	}
	return s.url
}

func (lb *WeightedRoundRobinLB) NextState() *targetState {
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return nil
	}
	targets := *ptr
	if len(targets) == 0 {
		return nil
	}

	totalWeight, weighted := int32(0), false
	for _, t := range targets {
		if t.weight > 0 {
			weighted = true
			if t.alive.Load() {
				totalWeight += t.weight
			}
		}
	}
	if !weighted {
		// No target carries a weight: the service was saved without any
		// (proto3's zero), which means "no preference", not "send nothing".
		// This used to answer 502 "no targets available" to every request.
		return lb.nextEqual(targets)
	}
	if totalWeight <= 0 {
		return nil // every weighted target is down; zero weights stay unused
	}
	n := atomic.AddUint64(&lb.current, 1)
	val := int32((n - 1) % uint64(totalWeight))
	currentSum := int32(0)
	for _, t := range targets {
		if t.weight <= 0 || !t.alive.Load() {
			continue
		}
		currentSum += t.weight
		if val < currentSum {
			return t
		}
	}
	return nil // defensive: loop should always return; no alive target
}

// nextEqual rotates through the alive targets with equal weight.
func (lb *WeightedRoundRobinLB) nextEqual(targets []*targetState) *targetState {
	alive := 0
	for _, t := range targets {
		if t.alive.Load() {
			alive++
		}
	}
	if alive == 0 {
		return nil
	}
	idx := int((atomic.AddUint64(&lb.current, 1) - 1) % uint64(alive))
	for _, t := range targets {
		if !t.alive.Load() {
			continue
		}
		if idx == 0 {
			return t
		}
		idx--
	}
	return nil
}

func (lb *WeightedRoundRobinLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	newTargets := make([]*targetState, len(targets))
	for i, t := range targets {
		newTargets[i] = newTargetStateFromTarget(t)
	}
	lb.targetsPtr.Store(&newTargets)
}

func (lb *WeightedRoundRobinLB) SetAlive(url string, alive bool) {
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

func (lb *WeightedRoundRobinLB) GetStats() []TargetStats {
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

func (lb *WeightedRoundRobinLB) RecordLatency(url string, latency float64) {
	// WeightedRoundRobinLB doesn't use latency for balancing.
}
