// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package proxy

import (
	"sync"
	"sync/atomic"

	"github.com/gsoultan/gateon/internal/ai"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AIPredictiveLB implements intelligent load balancing using AI-driven latency prediction.
// It uses a PredictorStrategy from internal/ai to select the best target.
type AIPredictiveLB struct {
	targetsPtr atomic.Pointer[[]*targetState]
	strategy   *ai.PredictorStrategy
	mu         sync.Mutex
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

// NextState returns the best target state based on predictive AI logic.
func (lb *AIPredictiveLB) NextState() *targetState {
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return nil
	}
	targets := *ptr

	if len(targets) == 0 {
		return nil
	}

	// Filter alive targets for prediction.
	alive := make([]*targetState, 0, len(targets))
	urls := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.alive.Load() {
			alive = append(alive, t)
			urls = append(urls, t.url)
		}
	}

	if len(alive) == 0 {
		return nil
	}

	// Use the AI strategy to pick the best URL.
	bestURL := lb.strategy.PredictBest(urls)
	for _, t := range alive {
		if t.url == bestURL {
			return t
		}
	}

	// Fallback to first alive target if prediction fails to match.
	return alive[0]
}

// UpdateWeightedTargets refreshes the target list.
func (lb *AIPredictiveLB) UpdateWeightedTargets(targets []*gateonv1.Target) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	newTargets := make([]*targetState, len(targets))
	for i, t := range targets {
		newTargets[i] = newTargetStateFromTarget(t)
	}
	lb.targetsPtr.Store(&newTargets)
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

// SetAlive marks a target as alive or dead based on health checks.
func (lb *AIPredictiveLB) SetAlive(url string, alive bool) {
	ptr := lb.targetsPtr.Load()
	if ptr == nil {
		return
	}
	for _, t := range *ptr {
		if t.url == url {
			t.alive.Store(alive)
			return
		}
	}
}

// RecordLatency logs a latency sample to the AI strategy.
func (lb *AIPredictiveLB) RecordLatency(url string, latency float64) {
	lb.strategy.RecordLatency(url, latency)
}
