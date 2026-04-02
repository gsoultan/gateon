package telemetry

import (
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

	snap, err := CollectMetricsSnapshot()
	if err != nil {
		t.Fatalf("CollectMetricsSnapshot() error: %v", err)
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

	p50 := estimatePercentile(families, 0.50, nil)
	if p50 <= 0 {
		t.Errorf("expected p50 > 0, got %f", p50)
	}

	p99 := estimatePercentile(families, 0.99, nil)
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
