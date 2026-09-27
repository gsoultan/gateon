// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/ai"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// installProductionPredictor installs the traffic predictor the way
// cmd/gateon does at startup. That install is unconditional, so every
// ai_predictive balancer in a running gateway has a predictor; a test that
// leaves it out exercises a configuration no deployment runs.
func installProductionPredictor(t *testing.T) {
	t.Helper()
	if err := ai.InitGlobalPredictor(context.Background(), ai.DefaultModelWasm); err != nil {
		t.Fatalf("install predictor: %v", err)
	}
	if ai.GlobalPredictor() == nil {
		t.Fatal("no predictor installed")
	}
}

func newAIBalancer(t *testing.T, urls ...string) LoadBalancer {
	t.Helper()
	targets := make([]*gateonv1.Target, len(urls))
	for i, u := range urls {
		targets[i] = &gateonv1.Target{Url: u, Weight: 1}
	}
	return NewDefaultLoadBalancerFactory().Create("ai_predictive", targets)
}

// closedLoop picks n targets in sequence and reports each pick's latency back
// the way ProxyHandler.recordMetrics does after every response.
func closedLoop(t *testing.T, lb LoadBalancer, n int, latency map[string]float64) map[string]int {
	t.Helper()
	got := map[string]int{}
	for range n {
		s := lb.NextState()
		if s == nil {
			t.Fatal("no target while all are alive")
		}
		got[s.url]++
		lb.RecordLatency(s.url, latency[s.url])
	}
	return got
}

// TestAIPredictiveSendsTrafficToTheFasterBackend: the balancer compared the
// predictor's spike score -- 0 whenever a backend's latency is steady -- as if
// it were a latency, and gave backends it had never measured a pessimistic
// 0.5 s. So the first target took every request and kept them however slow it
// was, while a backend a hundred times faster was never tried. The slow target
// is listed first on purpose: "index 0 wins" must not look like a correct pick.
func TestAIPredictiveSendsTrafficToTheFasterBackend(t *testing.T) {
	installProductionPredictor(t)
	const slow, fast = "http://slow", "http://fast"
	lb := newAIBalancer(t, slow, fast)

	// 300 ms: under the 0.5 s the balancer used to assume for a backend it had
	// not measured, so that assumption alone was enough to starve the fast one.
	got := closedLoop(t, lb, 1000, map[string]float64{slow: 0.3, fast: 0.005})
	if got[fast] < 900 {
		t.Errorf("fast backend (5 ms) got %d of 1000 requests, slow backend (300 ms) got %d; "+
			"want the fast one to take at least 900", got[fast], got[slow])
	}
}

// TestAIPredictiveSpreadsIdenticalBackends: with every backend equally fast
// there is nothing to predict, and the balancer must still balance. It sent
// every request to the first target.
func TestAIPredictiveSpreadsIdenticalBackends(t *testing.T) {
	installProductionPredictor(t)
	urls := []string{"http://a", "http://b", "http://c"}
	lb := newAIBalancer(t, urls...)

	latency := map[string]float64{}
	for _, u := range urls {
		latency[u] = 0.01
	}
	got := closedLoop(t, lb, 900, latency)
	for _, u := range urls {
		if got[u] < 200 {
			t.Errorf("identical backends: %s got %d of 900 requests (all: %v); want each to get at least 200", u, got[u], got)
		}
	}
}

// TestAIPredictiveMovesAwayFromASpike: the point of the predictor. A backend
// whose latency jumps well above its forecast must lose traffic to a steady
// one straight away, not after its average has caught up.
func TestAIPredictiveMovesAwayFromASpike(t *testing.T) {
	installProductionPredictor(t)
	const spiking, steady = "http://spiking", "http://steady"
	lb := newAIBalancer(t, spiking, steady)

	// Both settle at 20 ms.
	closedLoop(t, lb, 200, map[string]float64{spiking: 0.02, steady: 0.02})
	// Then one of them starts answering in two seconds.
	got := closedLoop(t, lb, 200, map[string]float64{spiking: 2.0, steady: 0.02})
	if got[spiking] > 5 {
		t.Errorf("after its latency jumped from 20 ms to 2 s the spiking backend still got %d of 200 requests; want at most 5", got[spiking])
	}
}

// TestAIPredictiveSpreadsConcurrentRequests: a slightly slower backend must
// still take a share while the faster one is busy. Requests in flight count
// against a target; ranking by latency alone sends a whole burst to one.
func TestAIPredictiveSpreadsConcurrentRequests(t *testing.T) {
	installProductionPredictor(t)
	const quick, slower = "http://quick", "http://slower"
	lb := newAIBalancer(t, quick, slower)
	closedLoop(t, lb, 50, map[string]float64{quick: 0.010, slower: 0.012})

	got := map[string]int{}
	for range 100 { // a burst: every request is still in flight when the next is routed
		s := lb.NextState()
		atomic.AddInt32(&s.activeConn, 1)
		got[s.url]++
	}
	if got[quick] < 30 || got[slower] < 30 {
		t.Errorf("100 concurrent requests over 10 ms and 12 ms backends = %v; want each to take at least 30", got)
	}
}

// TestAIPredictiveSkipsDeadTargets: a target the health check marked down
// gets nothing, however cheap it looks.
func TestAIPredictiveSkipsDeadTargets(t *testing.T) {
	installProductionPredictor(t)
	const down, up = "http://down", "http://up"
	lb := newAIBalancer(t, down, up)
	closedLoop(t, lb, 20, map[string]float64{down: 0.001, up: 0.5})
	lb.SetAlive(down, false)
	if got := closedLoop(t, lb, 50, map[string]float64{down: 0.001, up: 0.5}); got[down] != 0 {
		t.Errorf("a dead target got %d of 50 requests", got[down])
	}
}

// TestAIPredictiveForgetsRemovedTargets: the balancer's latency memory is
// bounded by its configured targets, not by every target it ever had.
func TestAIPredictiveForgetsRemovedTargets(t *testing.T) {
	installProductionPredictor(t)
	const kept, removed = "http://kept", "http://removed"
	lb, ok := newAIBalancer(t, kept, removed).(*AIPredictiveLB)
	if !ok {
		t.Fatal("ai_predictive did not build an *AIPredictiveLB")
	}
	closedLoop(t, lb, 20, map[string]float64{kept: 0.01, removed: 0.01})
	lb.UpdateWeightedTargets([]*gateonv1.Target{{Url: kept, Weight: 1}})
	now := time.Now()
	if _, ok := lb.strategy.Estimate(removed, now); ok {
		t.Error("a target removed from the service is still remembered")
	}
	if _, ok := lb.strategy.Estimate(kept, now); !ok {
		t.Error("a target still configured was forgotten")
	}
}
