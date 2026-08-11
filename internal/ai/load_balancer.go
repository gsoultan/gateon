// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"context"
	"sync"
)

// LatencySignature represents the historical latency pattern of a backend target.
type LatencySignature struct {
	history []float64
	mu      sync.RWMutex
}

// PredictorStrategy provides AI-driven selection logic for load balancing.
// It tracks latency signatures and predicts the best target to minimize latency.
type PredictorStrategy struct {
	signatures sync.Map // map[string]*LatencySignature
	predictor  TrafficPredictor
	ctx        context.Context
}

// NewPredictorStrategy creates a new AI-based predictor strategy.
func NewPredictorStrategy() *PredictorStrategy {
	return &PredictorStrategy{
		ctx: context.Background(),
	}
}

// SetPredictor sets the optional WASM-based traffic predictor.
func (s *PredictorStrategy) SetPredictor(p TrafficPredictor) {
	s.predictor = p
}

// RecordLatency adds a new latency sample for a specific backend URL.
func (s *PredictorStrategy) RecordLatency(url string, latencySeconds float64) {
	val, ok := s.signatures.Load(url)
	if !ok {
		val = &LatencySignature{history: make([]float64, 0, 100)}
		s.signatures.Store(url, val)
	}
	sig := val.(*LatencySignature)
	sig.mu.Lock()
	defer sig.mu.Unlock()
	sig.history = append(sig.history, latencySeconds)
	if len(sig.history) > 100 {
		sig.history = sig.history[1:]
	}
}

// PredictBest selects the best URL from the provided list based on predicted latency.
func (s *PredictorStrategy) PredictBest(urls []string) string {
	if len(urls) == 0 {
		return ""
	}

	var bestURL string
	minLatency := 1e9 // High initial value

	for _, url := range urls {
		predicted := s.predictLatency(url)
		if predicted < minLatency {
			minLatency = predicted
			bestURL = url
		}
	}

	// If no bestURL was found (shouldn't happen with non-empty urls), return the first one.
	if bestURL == "" && len(urls) > 0 {
		return urls[0]
	}

	return bestURL
}

func (s *PredictorStrategy) predictLatency(url string) float64 {
	val, ok := s.signatures.Load(url)
	if !ok {
		return 0.5 // Default baseline latency for unknown targets
	}
	sig := val.(*LatencySignature)
	sig.mu.RLock()
	defer sig.mu.RUnlock()

	if len(sig.history) == 0 {
		return 0.5
	}

	// If a WASM predictor is available, use it for more complex patterns.
	if s.predictor != nil {
		if pred, err := s.predictor.Predict(s.ctx, sig.history); err == nil {
			return pred
		}
	}

	// Simple Exponential Moving Average (EMA) as a fallback.
	var ema float64
	alpha := 0.3
	ema = sig.history[0]
	for i := 1; i < len(sig.history); i++ {
		ema = alpha*sig.history[i] + (1-alpha)*ema
	}
	return ema
}
