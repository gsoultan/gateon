// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ai

import (
	"context"
	"math"
	"testing"
	"time"
)

type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time { return c.t }

func newTestStrategy(p TrafficPredictor) (*PredictorStrategy, *stepClock) {
	c := &stepClock{t: time.Unix(1_700_000_000, 0)}
	s := NewPredictorStrategy()
	s.now = c.now
	if p != nil {
		s.SetPredictor(p)
	}
	return s, c
}

// fixedScore is a predictor that always answers the same spike score.
type fixedScore float64

func (f fixedScore) Predict(context.Context, []float64) (float64, error) { return float64(f), nil }
func (fixedScore) Close(context.Context) error                           { return nil }

// TestEstimateIsALatencyNotASpikeScore: a backend answering in 500 ms every
// time is estimated at 500 ms. Its spike score is 0, and that 0 is what the
// balancer used to rank it by.
func TestEstimateIsALatencyNotASpikeScore(t *testing.T) {
	s, c := newTestStrategy(&NativePredictor{})
	for range 20 {
		s.RecordLatency("slow", 0.5)
	}
	if est, ok := s.Estimate("slow", c.t); !ok || math.Abs(est-0.5) > 1e-9 {
		t.Fatalf("steady 500 ms backend: Estimate = %v, %v; want 0.5, true", est, ok)
	}
}

func TestAnUnmeasuredBackendHasNoEstimate(t *testing.T) {
	s, c := newTestStrategy(&NativePredictor{})
	if est, ok := s.Estimate("never", c.t); ok {
		t.Fatalf("Estimate of a backend never sampled = %v, true; want false", est)
	}
}

// TestASpikeRaisesTheEstimateAboveTheAverage is what the predictor is for: a
// jump well above the trend prices the backend higher than its average alone.
func TestASpikeRaisesTheEstimateAboveTheAverage(t *testing.T) {
	with, c := newTestStrategy(&NativePredictor{})
	without, _ := newTestStrategy(nil)
	for _, x := range []float64{0.02, 0.02, 0.02, 0.02, 0.02, 2.0} {
		with.RecordLatency("b", x)
		without.RecordLatency("b", x)
	}
	w, _ := with.Estimate("b", c.t)
	wo, _ := without.Estimate("b", c.t)
	if w < 1.5*wo {
		t.Errorf("after a 20 ms -> 2 s jump: estimate with predictor %v, without %v; want the spike to weigh at least 1.5x", w, wo)
	}
}

// TestAModelScoreIsClamped: a custom model can weight a backend, but a
// negative score must not price it below zero -- which would draw every
// request -- and a huge one must not price it out of the pool.
func TestAModelScoreIsClamped(t *testing.T) {
	for _, tc := range []struct {
		score float64
		want  float64 // multiple of the plain average
	}{{-5, 1}, {math.NaN(), 1}, {0.5, 1.5}, {50, 2}} {
		s, c := newTestStrategy(fixedScore(tc.score))
		s.RecordLatency("b", 0.1)
		if est, _ := s.Estimate("b", c.t); math.Abs(est-0.1*tc.want) > 1e-9 {
			t.Errorf("model score %v: estimate %v, want %v", tc.score, est, 0.1*tc.want)
		}
	}
}

// TestAnIdleEstimateDecays is what gets a backend retried after one slow
// answer: nothing else ever sends it traffic, so nothing else would ever
// correct the estimate.
func TestAnIdleEstimateDecays(t *testing.T) {
	s, c := newTestStrategy(nil)
	s.RecordLatency("b", 0.4)
	for _, tc := range []struct {
		idle time.Duration
		want float64
	}{{0, 0.4}, {estimateHalfLife, 0.2}, {3 * estimateHalfLife, 0.05}} {
		if got, _ := s.Estimate("b", c.t.Add(tc.idle)); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("idle %v: estimate %v, want %v", tc.idle, got, tc.want)
		}
	}
}

// TestARecoveredBackendIsPricedByItsNewAnswers: when an idle backend is
// retried and answers fast, the average starts from where the balancer's
// decayed view of it was, not from the stale peak -- otherwise a recovered
// backend has to earn its way down one probe per few half-lives.
func TestARecoveredBackendIsPricedByItsNewAnswers(t *testing.T) {
	s, c := newTestStrategy(nil)
	s.RecordLatency("b", 0.5)
	c.t = c.t.Add(10 * estimateHalfLife)
	s.RecordLatency("b", 0.005)
	if got, _ := s.Estimate("b", c.t); got > 0.01 {
		t.Errorf("retried after 10 half-lives and answered in 5 ms: estimate %v, want under 0.01", got)
	}
}

// TestNonsenseSamplesAreIgnored: one NaN would otherwise poison the average
// for good, and every comparison against NaN is false, so the backend would
// win or lose every pick by accident.
func TestNonsenseSamplesAreIgnored(t *testing.T) {
	for _, x := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		s, c := newTestStrategy(nil)
		s.RecordLatency("b", 0.1)
		s.RecordLatency("b", x)
		if got, _ := s.Estimate("b", c.t); math.IsNaN(got) || math.Abs(got-0.1) > 1e-9 {
			t.Errorf("estimate after a %v sample = %v, want 0.1", x, got)
		}
	}
}

// TestRetainForgetsRemovedBackends bounds the strategy's memory by the
// balancer's configured targets.
func TestRetainForgetsRemovedBackends(t *testing.T) {
	s, c := newTestStrategy(nil)
	s.RecordLatency("a", 0.01)
	s.RecordLatency("b", 0.01)
	s.Retain([]string{"b"})
	if _, ok := s.Estimate("a", c.t); ok {
		t.Error("a backend removed from the balancer is still remembered")
	}
	if _, ok := s.Estimate("b", c.t); !ok {
		t.Error("a backend still configured was forgotten")
	}
}

func TestHistoryIsBoundedAndKeepsTheNewest(t *testing.T) {
	s, _ := newTestStrategy(nil)
	for i := range 3 * historySize {
		s.RecordLatency("b", float64(i))
	}
	h := s.signature("b").history
	if len(h) != historySize || h[0] != float64(2*historySize) || h[historySize-1] != float64(3*historySize-1) {
		t.Errorf("history: len %d, first %v, last %v; want %d samples from %d to %d",
			len(h), h[0], h[len(h)-1], historySize, 2*historySize, 3*historySize-1)
	}
}
