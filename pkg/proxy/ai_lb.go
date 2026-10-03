// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/ai"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// aiCostFloor keeps requests in flight counting against a target whose
// latency estimate is still zero, so a burst spreads instead of piling onto
// it before its first answer.
const aiCostFloor = 1e-6

// AIPredictiveLB implements intelligent load balancing using AI-driven latency prediction.
// It uses a PredictorStrategy from internal/ai to select the best target.
type AIPredictiveLB struct {
	targetsPtr atomic.Pointer[[]*targetState]
	strategy   *ai.PredictorStrategy
	mu         sync.Mutex
	ties       atomic.Uint64 // rotates where each scan starts, so equal costs take turns
}

// NewAIPredictiveLB creates a new AI-driven load balancer.
func NewAIPredictiveLB(targets []*gateonv1.Target) *AIPredictiveLB {
	strategy := ai.NewPredictorStrategy()
	if p := ai.GlobalPredictor(); p != nil {
		strategy.SetPredictor(p)
	}
	lb := &AIPredictiveLB{
		strategy: strategy,
	}
	lb.UpdateWeightedTargets(targets)
	return lb
}

// Next returns the URL of the next selected target.
func (lb *AIPredictiveLB) Next() string {
	s := lb.NextState()
	if s == nil {
		return ""
	}
	return s.url
}

// NextState routes to the alive target with the lowest cost: its predicted
// latency times one more than its requests in flight.
//
// It used to send every request to the first target. Backends it had never
// measured were priced at a pessimistic 0.5 s, so once the first one answered
// faster than that the others were never tried; ties went to the first target
// in the list; and the predictor's spike score stood in for latency, which
// pinned traffic to whichever backend was steadiest, however slow. Now a
// target not yet measured is priced like the best measured one, so each is
// tried, and each scan starts one target further on, so equal costs take
// turns. Before anything is measured this is least-connections.
func (lb *AIPredictiveLB) NextState() *targetState {
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return nil
	}
	targets := *ptr
	if len(targets) == 0 {
		return nil
	}
	now := time.Now()
	prior := lb.bestEstimate(targets, now)
	idx := int((lb.ties.Add(1) - 1) % uint64(len(targets)))
	var best *targetState
	var bestCost float64
	for range targets {
		t := targets[idx]
		if idx++; idx == len(targets) {
			idx = 0
		}
		if !t.alive.Load() {
			continue
		}
		if c := lb.cost(t, now, prior); best == nil || c < bestCost {
			best, bestCost = t, c
		}
	}
	return best
}

// bestEstimate is the lowest latency estimate among alive measured targets,
// or 0 when none has been measured yet.
func (lb *AIPredictiveLB) bestEstimate(targets []*targetState, now time.Time) float64 {
	best, found := 0.0, false
	for _, t := range targets {
		if !t.alive.Load() {
			continue
		}
		if est, ok := lb.strategy.Estimate(t.url, now); ok && (!found || est < best) {
			best, found = est, true
		}
	}
	return best
}

// cost prices t for the next request, using prior for a target that has not
// been measured yet.
func (lb *AIPredictiveLB) cost(t *targetState, now time.Time, prior float64) float64 {
	est, ok := lb.strategy.Estimate(t.url, now)
	if !ok {
		est = prior
	}
	return (est + aiCostFloor) * float64(atomic.LoadInt32(&t.activeConn)+1)
}

// UpdateWeightedTargets refreshes the target list.
func (lb *AIPredictiveLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	newTargets := make([]*targetState, len(targets))
	urls := make([]string, len(targets))
	for i, t := range targets {
		newTargets[i] = newTargetStateFromTarget(t)
		urls[i] = newTargets[i].url
	}
	lb.targetsPtr.Store(&newTargets)
	lb.strategy.Retain(urls)
}

// GetStats returns current statistics for all targets.
func (lb *AIPredictiveLB) GetStats() []TargetStats {
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

// SetAlive marks a target as alive or dead based on health checks, and
// reports the transition to the circuit-breaker feed as the other policies do;
// ai_predictive services' outages never appeared there.
func (lb *AIPredictiveLB) SetAlive(url string, alive bool) {
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

// RecordLatency logs a latency sample to the AI strategy.
func (lb *AIPredictiveLB) RecordLatency(url string, latency float64) {
	lb.strategy.RecordLatency(url, latency)
}

func (lb *AIPredictiveLB) states() []*targetState {
	if ptr := lb.targetsPtr.Load(); ptr != nil {
		return *ptr
	}
	return nil
}
