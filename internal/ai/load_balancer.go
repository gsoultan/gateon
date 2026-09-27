// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"context"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// historySize bounds the latency window each backend keeps for the predictor.
const historySize = 100

// ewmaAlpha is the weight of the newest sample in a backend's latency average.
const ewmaAlpha = 0.3

// estimateHalfLife is how long a backend's latency estimate takes to halve
// while it receives no traffic.
//
// Without it one slow answer -- a cold start, a GC pause, a first TLS
// handshake -- priced a backend out for good: nothing was sent to it again, so
// nothing could ever correct the estimate. Decaying toward zero means an idle
// backend is retried after a few half-lives, and one that is still slow costs
// a single probe per few half-lives rather than a share of the traffic.
const estimateHalfLife = 10 * time.Second

// LatencySignature is one backend's latency history and the estimate the
// balancer ranks it by.
type LatencySignature struct {
	mu      sync.Mutex
	history []float64 // oldest first, at most historySize samples
	ewma    float64

	// Written under mu when a sample arrives, read without it when a request
	// is routed.
	estimate atomic.Uint64 // math.Float64bits of the spike-weighted average, seconds
	stamp    atomic.Int64  // UnixNano of the newest sample; 0 until the first
}

// PredictorStrategy ranks backends by predicted latency for the ai_predictive
// load-balancing policy.
type PredictorStrategy struct {
	signatures sync.Map // map[string]*LatencySignature, bounded by Retain
	predictor  TrafficPredictor
	ctx        context.Context
	now        func() time.Time // injectable for tests
}

// NewPredictorStrategy creates a new AI-based predictor strategy.
func NewPredictorStrategy() *PredictorStrategy {
	return &PredictorStrategy{
		ctx: context.Background(),
		now: time.Now,
	}
}

// SetPredictor sets the traffic predictor whose spike score weights each
// backend's estimate.
func (s *PredictorStrategy) SetPredictor(p TrafficPredictor) {
	s.predictor = p
}

// RecordLatency adds a latency sample for url and re-prices it.
//
// The predictor answers a different question from the one the balancer asks:
// its output is a spike score in [0, 1], how far the newest sample sits above
// the trend's forecast, and it is 0 whenever latency is steady. It used to be
// returned as the backend's latency, so a backend answering in 500 ms every
// time scored 0 and beat one answering in 5 ms with any jitter at all. It is
// now a weight on the backend's average: up to double when the latest sample
// is a clear spike, no change when it is not.
func (s *PredictorStrategy) RecordLatency(url string, latencySeconds float64) {
	if math.IsNaN(latencySeconds) || math.IsInf(latencySeconds, 0) || latencySeconds < 0 {
		return
	}
	sig := s.signature(url)
	now := s.now()

	sig.mu.Lock()
	defer sig.mu.Unlock()
	sig.observe(latencySeconds, now)
	estimate := sig.ewma * (1 + s.spike(sig.history))
	sig.estimate.Store(math.Float64bits(estimate))
	sig.stamp.Store(now.UnixNano())
}

// Estimate returns url's predicted latency in seconds as of now, and false if
// url has never been sampled.
func (s *PredictorStrategy) Estimate(url string, now time.Time) (float64, bool) {
	v, ok := s.signatures.Load(url)
	if !ok {
		return 0, false
	}
	sig, ok := v.(*LatencySignature)
	if !ok {
		return 0, false
	}
	stamp := sig.stamp.Load()
	if stamp == 0 {
		return 0, false
	}
	return decay(math.Float64frombits(sig.estimate.Load()), now.UnixNano()-stamp), true
}

// Retain forgets every backend not in urls, so the strategy's memory follows
// the balancer's configured targets rather than every target it ever had.
func (s *PredictorStrategy) Retain(urls []string) {
	s.signatures.Range(func(k, _ any) bool {
		if url, ok := k.(string); !ok || !slices.Contains(urls, url) {
			s.signatures.Delete(k)
		}
		return true
	})
}

// signature returns url's signature, creating it on first use. Load first:
// LoadOrStore alone would build a throwaway signature on every response.
func (s *PredictorStrategy) signature(url string) *LatencySignature {
	if v, ok := s.signatures.Load(url); ok {
		if sig, ok := v.(*LatencySignature); ok {
			return sig
		}
	}
	v, _ := s.signatures.LoadOrStore(url, &LatencySignature{history: make([]float64, 0, historySize)})
	sig, _ := v.(*LatencySignature)
	return sig
}

// spike returns the predictor's score for history, clamped to [0, 1] so a
// custom model can weight a backend but never price it below zero or out of
// the pool entirely. A model that fails contributes nothing.
func (s *PredictorStrategy) spike(history []float64) float64 {
	if s.predictor == nil {
		return 0
	}
	score, err := s.predictor.Predict(s.ctx, history)
	if err != nil || math.IsNaN(score) {
		return 0
	}
	return min(max(score, 0), 1)
}

// observe appends x to the history and folds it into the average. The average
// first decays for the time the backend sat idle, as the balancer saw it
// decay, so a backend that recovered while idle is priced by its new answers
// instead of having to work its way down from a stale peak.
func (sig *LatencySignature) observe(x float64, now time.Time) {
	if len(sig.history) == historySize {
		copy(sig.history, sig.history[1:])
		sig.history[historySize-1] = x
	} else {
		sig.history = append(sig.history, x)
	}
	stamp := sig.stamp.Load()
	if stamp == 0 {
		sig.ewma = x
		return
	}
	sig.ewma = ewmaAlpha*x + (1-ewmaAlpha)*decay(sig.ewma, now.UnixNano()-stamp)
}

// decay halves v for every estimateHalfLife in idleNanos.
func decay(v float64, idleNanos int64) float64 {
	if idleNanos <= 0 {
		return v
	}
	return v * math.Exp2(-float64(idleNanos)/float64(estimateHalfLife))
}
