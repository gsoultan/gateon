// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestCollectMetricsSnapshot(t *testing.T) {
	// Seed some metrics so the snapshot has data to collect.
	// gateon- prefix is for Golden Signals (entrypoints).
	RequestsTotal.WithLabelValues("gateon-test", "test-svc", "GET", "200").Add(100)
	RequestsTotal.WithLabelValues("gateon-test", "test-svc", "GET", "500").Add(5)
	RequestBytesTotal.WithLabelValues("gateon-test", "in").Add(1024)
	RequestBytesTotal.WithLabelValues("gateon-test", "out").Add(4096)
	RequestsInFlight.WithLabelValues("gateon-test").Set(3)
	RequestDurationSeconds.WithLabelValues("gateon-test", "test-svc", "GET").Observe(0.05)
	RequestDurationSeconds.WithLabelValues("gateon-test", "test-svc", "GET").Observe(0.15)

	// Non-prefixed for Route Metrics.
	RequestsTotal.WithLabelValues("test-route", "test-svc", "GET", "200").Add(100)
	RequestsTotal.WithLabelValues("test-route", "test-svc", "GET", "500").Add(5)
	RequestDurationSeconds.WithLabelValues("test-route", "test-svc", "GET").Observe(0.05)
	RequestDurationSeconds.WithLabelValues("test-route", "test-svc", "GET").Observe(0.15)
	RequestBytesTotal.WithLabelValues("test-route", "in").Add(1024)
	RequestBytesTotal.WithLabelValues("test-route", "out").Add(4096)
	RequestsInFlight.WithLabelValues("test-route").Set(3)
	TargetHealth.WithLabelValues("test-route", "http://localhost:8080").Set(1)
	ActiveConnections.WithLabelValues("http://localhost:8080").Set(7)
	MiddlewareCacheHitsTotal.WithLabelValues("test-route").Add(50)
	MiddlewareCacheMissesTotal.WithLabelValues("test-route").Add(10)
	MiddlewareRateLimitRejectedTotal.WithLabelValues("test-route", "ip").Add(3)

	snap, err := CollectMetricsSnapshot(t.Context(), 10, 0)
	if err != nil {
		t.Fatalf("CollectMetricsSnapshot(10, 0) error: %v", err)
	}

	// Golden signals
	gs := snap.GoldenSignals
	if gs.RequestsTotal < 105 {
		t.Errorf("expected requests_total >= 105, got %f", gs.RequestsTotal)
	}
	if gs.ErrorsTotal < 5 {
		t.Errorf("expected errors_total >= 5, got %f", gs.ErrorsTotal)
	}
	if gs.ErrorRate <= 0 {
		t.Error("expected error_rate > 0")
	}
	if gs.BytesInTotal < 1024 {
		t.Errorf("expected bytes_in >= 1024, got %f", gs.BytesInTotal)
	}
	if gs.BytesOutTotal < 4096 {
		t.Errorf("expected bytes_out >= 4096, got %f", gs.BytesOutTotal)
	}
	if gs.InFlightTotal < 3 {
		t.Errorf("expected in_flight >= 3, got %f", gs.InFlightTotal)
	}

	// Route metrics
	if len(snap.RouteMetrics) == 0 {
		t.Fatal("expected at least one route metric")
	}
	var found bool
	for _, rm := range snap.RouteMetrics {
		if rm.Route == "test-route" {
			found = true
			if rm.Requests < 105 {
				t.Errorf("route requests expected >= 105, got %f", rm.Requests)
			}
			if rm.Errors < 5 {
				t.Errorf("route errors expected >= 5, got %f", rm.Errors)
			}
			if len(rm.StatusCodes) == 0 {
				t.Error("expected status codes map to be populated")
			}
			if rm.AvgLatency <= 0 {
				t.Error("expected avg_latency > 0")
			}
		}
	}
	if !found {
		t.Error("test-route not found in route metrics")
	}

	// Middleware
	mw := snap.Middleware
	if mw.CacheHits < 50 {
		t.Errorf("expected cache_hits >= 50, got %f", mw.CacheHits)
	}
	if mw.CacheMisses < 10 {
		t.Errorf("expected cache_misses >= 10, got %f", mw.CacheMisses)
	}
	if mw.CacheHitRate <= 0 {
		t.Error("expected cache_hit_rate > 0")
	}
	if len(mw.RateLimitRejected) == 0 {
		t.Error("expected rate_limit_rejected entries")
	}

	// Targets
	if len(snap.Targets) == 0 {
		t.Fatal("expected at least one target metric")
	}
	foundTarget := false
	for _, tgt := range snap.Targets {
		if tgt.Target == "http://localhost:8080" {
			foundTarget = true
			if !tgt.Healthy {
				t.Error("expected target to be healthy")
			}
		}
	}
	if !foundTarget {
		t.Error("http://localhost:8080 target not found")
	}
}

func TestEstimatePercentile(t *testing.T) {
	// Observe known values so we can test percentile estimation.
	hist := RequestDurationSeconds.WithLabelValues("p-test", "svc", "GET")
	for range 100 {
		hist.Observe(0.01)
	}
	for range 90 {
		hist.Observe(0.1)
	}
	for range 10 {
		hist.Observe(1.0)
	}

	families, err := gatherFamily("gateon_request_duration_seconds")
	if err != nil {
		t.Fatal(err)
	}

	p := estimatePercentiles(families, []float64{0.50, 0.99}, nil)
	p50 := p[0]
	if p50 <= 0 {
		t.Errorf("expected p50 > 0, got %f", p50)
	}

	p99 := p[1]
	if p99 <= p50 {
		t.Errorf("expected p99 (%f) > p50 (%f)", p99, p50)
	}
}

func gatherFamily(name string) (*dto.MetricFamily, error) {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}
	for _, f := range families {
		if f.GetName() == name {
			return f, nil
		}
	}
	return nil, nil
}

// routeRequests reports the request count snap holds for route, or -1 when the
// route is absent.
func routeRequests(snap *MetricsSnapshot, route string) float64 {
	for _, rm := range snap.RouteMetrics {
		if rm.Route == route {
			return rm.Requests
		}
	}
	return -1
}

// TestPublishedSnapshotSurvivesLaterRefreshes pins down that a snapshot handed
// out by GetLastSnapshot stays what it was when it was handed out.
//
// The snapshot loop used to return the previous snapshot to a sync.Pool the
// moment it swapped in a new one, while that pointer was still held by every
// /v1/watch and /v1/diag/metrics/watch subscriber's channel, by whoever had
// just called CollectMetricsSnapshot, and by the aggregator. Two refreshes
// later the pool handed the same object back, Reset zeroed it and the collector
// refilled it in place -- so a slow SSE client serialised a snapshot that was
// being rewritten underneath it, and on the minimal tier, where light refreshes
// alias the previous snapshot's slices, the live snapshot's traffic history and
// security insights were zeroed while the dashboard was reading them.
func TestPublishedSnapshotSurvivesLaterRefreshes(t *testing.T) {
	// Own the store singleton: a store left open by an earlier test would put
	// SQL round-trips into every refresh and blur what this test measures.
	_ = ClosePathStatsStore(context.Background())

	const route = "snapshot-recycle-route"
	counter := RequestsTotal.WithLabelValues(route, "svc", "GET", "200")
	counter.Add(7)

	for round := range 5 {
		refreshSnapshot(t.Context(), true)
		held := GetLastSnapshot()
		want := routeRequests(held, route)
		if want < 0 {
			t.Fatalf("round %d: route %q missing from a fresh snapshot", round, route)
		}

		// The metrics move on and the loop refreshes twice more, as it does
		// every few seconds in production while a reader still holds `held`.
		counter.Add(1000)
		refreshSnapshot(t.Context(), true)
		refreshSnapshot(t.Context(), true)

		if got := routeRequests(held, route); got != want {
			t.Fatalf("round %d: a snapshot handed to a reader was rewritten by later refreshes: route %q read %v when handed out and reads %v now",
				round, route, want, got)
		}
	}
}
