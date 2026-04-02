package telemetry

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func getCounterValue(t *testing.T, counter *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := counter.WithLabelValues(labels...).Write(m); err != nil {
		t.Fatalf("failed to read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

func getGaugeValue(t *testing.T, gauge *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := gauge.WithLabelValues(labels...).Write(m); err != nil {
		t.Fatalf("failed to read gauge: %v", err)
	}
	return m.GetGauge().GetValue()
}

func TestRequestsTotal(t *testing.T) {
	before := getCounterValue(t, RequestsTotal, "test-route", "test-svc", "GET", "200")
	RequestsTotal.WithLabelValues("test-route", "test-svc", "GET", "200").Inc()
	after := getCounterValue(t, RequestsTotal, "test-route", "test-svc", "GET", "200")
	if after-before != 1 {
		t.Errorf("expected increment of 1, got %f", after-before)
	}
}

func TestRequestBytesTotal(t *testing.T) {
	before := getCounterValue(t, RequestBytesTotal, "test-route", "in")
	RequestBytesTotal.WithLabelValues("test-route", "in").Add(1024)
	after := getCounterValue(t, RequestBytesTotal, "test-route", "in")
	if after-before != 1024 {
		t.Errorf("expected increment of 1024, got %f", after-before)
	}
}

func TestMiddlewareCounters(t *testing.T) {
	tests := []struct {
		name    string
		counter *prometheus.CounterVec
		labels  []string
	}{
		{"ratelimit", MiddlewareRateLimitRejectedTotal, []string{"route1", "local"}},
		{"waf", MiddlewareWAFBlockedTotal, []string{"route1", "942100"}},
		{"cache_hits", MiddlewareCacheHitsTotal, []string{"route1"}},
		{"cache_misses", MiddlewareCacheMissesTotal, []string{"route1"}},
		{"auth_failures", MiddlewareAuthFailuresTotal, []string{"route1", "jwt"}},
		{"turnstile", MiddlewareTurnstileTotal, []string{"route1", "fail"}},
		{"geoip", MiddlewareGeoIPBlockedTotal, []string{"route1", "CN"}},
		{"hmac", MiddlewareHMACFailuresTotal, []string{"route1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := getCounterValue(t, tt.counter, tt.labels...)
			tt.counter.WithLabelValues(tt.labels...).Inc()
			after := getCounterValue(t, tt.counter, tt.labels...)
			if after-before != 1 {
				t.Errorf("expected increment of 1, got %f", after-before)
			}
		})
	}
}

func TestRequestDurationHistogram(t *testing.T) {
	RequestDurationSeconds.WithLabelValues("test-route", "test-svc", "GET").Observe(0.05)
	RequestDurationSeconds.WithLabelValues("test-route", "test-svc", "GET").Observe(0.15)

	m := &dto.Metric{}
	if err := RequestDurationSeconds.WithLabelValues("test-route", "test-svc", "GET").(prometheus.Histogram).Write(m); err != nil {
		t.Fatalf("failed to read histogram: %v", err)
	}
	if m.GetHistogram().GetSampleCount() < 2 {
		t.Errorf("expected at least 2 samples, got %d", m.GetHistogram().GetSampleCount())
	}
}

func TestGauges(t *testing.T) {
	RequestsInFlight.WithLabelValues("route-gauge").Inc()
	RequestsInFlight.WithLabelValues("route-gauge").Inc()
	val := getGaugeValue(t, RequestsInFlight, "route-gauge")
	if val < 2 {
		t.Errorf("expected at least 2, got %f", val)
	}
	RequestsInFlight.WithLabelValues("route-gauge").Dec()
	val = getGaugeValue(t, RequestsInFlight, "route-gauge")
	if val < 1 {
		t.Errorf("expected at least 1, got %f", val)
	}
}

func TestTargetHealth(t *testing.T) {
	TargetHealth.WithLabelValues("route1", "http://backend:8080").Set(1)
	val := getGaugeValue(t, TargetHealth, "route1", "http://backend:8080")
	if val != 1 {
		t.Errorf("expected 1, got %f", val)
	}

	TargetHealth.WithLabelValues("route1", "http://backend:8080").Set(0)
	val = getGaugeValue(t, TargetHealth, "route1", "http://backend:8080")
	if val != 0 {
		t.Errorf("expected 0, got %f", val)
	}
}

func TestTLSCertificateExpirySeconds(t *testing.T) {
	expiry := float64(time.Now().Add(30 * 24 * time.Hour).Unix())
	TLSCertificateExpirySeconds.WithLabelValues("example.com", "cert.pem").Set(expiry)
	val := getGaugeValue(t, TLSCertificateExpirySeconds, "example.com", "cert.pem")
	if val != expiry {
		t.Errorf("expected %f, got %f", expiry, val)
	}
}

func TestInitStartTime(t *testing.T) {
	InitStartTime()
	if startTime.IsZero() {
		t.Error("expected startTime to be set")
	}
}

func TestStartSystemMetricsCollector(t *testing.T) {
	stop := make(chan struct{})
	StartSystemMetricsCollector(stop)
	// Let it tick once
	time.Sleep(50 * time.Millisecond)
	close(stop)
}
