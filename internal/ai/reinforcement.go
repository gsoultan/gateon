// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
)

// IPState holds the reinforcement learning state for a specific IP address.
type IPState struct {
	QValue       float64
	LastFeedback time.Time
	mu           sync.Mutex
}

// ReinforcementLearningLimiter implements RL logic for adaptive rate limiting.
// It learns from security feedback to dynamically adjust eBPF rate limits.
type ReinforcementLearningLimiter struct {
	ebpf   ebpf.Manager
	states sync.Map // map[string]*IPState
}

// NewReinforcementLearningLimiter creates a new RL-based rate limiter.
func NewReinforcementLearningLimiter(ebpfMgr ebpf.Manager) *ReinforcementLearningLimiter {
	return &ReinforcementLearningLimiter{
		ebpf: ebpfMgr,
	}
}

// ProcessFeedback updates the RL model with feedback score (0.0 to 1.0) and adjusts rate limits.
func (rl *ReinforcementLearningLimiter) ProcessFeedback(ip string, score float64) {
	val, ok := rl.states.Load(ip)
	if !ok {
		val = &IPState{QValue: 0.0, LastFeedback: time.Now()}
		rl.states.Store(ip, val)
	}
	state := val.(*IPState)

	state.mu.Lock()
	defer state.mu.Unlock()

	// Q-Learning update rule (simplified): Q(s) = Q(s) + alpha * (reward - Q(s))
	// Here, the 'score' from Neural Sentinel acts as the perceived 'threat reward'.
	alpha := 0.2
	state.QValue = state.QValue + alpha*(score-state.QValue)
	state.LastFeedback = time.Now()

	// Act on the learned Q-Value by adjusting eBPF adaptive rate limits.
	rl.applyAdaptiveLimit(ip, state.QValue)
}

func (rl *ReinforcementLearningLimiter) applyAdaptiveLimit(ip string, qValue float64) {
	if rl.ebpf == nil {
		return
	}

	var interval time.Duration
	switch {
	case qValue > 0.9:
		// Critical threat: 10ms interval (very aggressive)
		interval = 10 * time.Millisecond
	case qValue > 0.7:
		// High threat: 50ms interval
		interval = 50 * time.Millisecond
	case qValue > 0.4:
		// Moderate threat: 200ms interval
		interval = 200 * time.Millisecond
	default:
		// Low threat: no adaptive limiting needed, or clear it
		interval = 0
	}

	if interval > 0 {
		_ = rl.ebpf.SetAdaptiveRateLimit(ip, interval)
	}
}
