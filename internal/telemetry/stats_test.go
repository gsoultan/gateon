package telemetry

import (
	"testing"
)

func TestPathStats(t *testing.T) {
	// Reset stats for test
	pathStatsMap = make(map[string]*pathStatsInternal)

	RecordPathRequest("example.com", "/api", 0.1, 100)
	RecordPathRequest("example.com", "/api", 0.2, 150)
	RecordPathRequest("other.com", "/", 0.5, 300)

	stats := GetPathStats(t.Context())
	if len(stats) != 2 {
		t.Errorf("expected 2 stats, got %d", len(stats))
	}

	for _, s := range stats {
		if s.Host == "example.com" && s.Path == "/api" {
			if s.RequestCount != 2 {
				t.Errorf("expected 2 requests for example.com/api, got %d", s.RequestCount)
			}
			if s.BytesTotal != 250 {
				t.Errorf("expected 250 bytes total for example.com/api, got %d", s.BytesTotal)
			}
			if s.AvgLatency != 0.15 {
				t.Errorf("expected 0.15 avg latency for example.com/api, got %f", s.AvgLatency)
			}
		} else if s.Host == "other.com" && s.Path == "/" {
			if s.RequestCount != 1 {
				t.Errorf("expected 1 request for other.com/, got %d", s.RequestCount)
			}
			if s.BytesTotal != 300 {
				t.Errorf("expected 300 bytes total for other.com/, got %d", s.BytesTotal)
			}
			if s.AvgLatency != 0.5 {
				t.Errorf("expected 0.5 avg latency for other.com/, got %f", s.AvgLatency)
			}
		}
	}
}

func TestRecordPathRequest_ExcludesInternalAPIPaths(t *testing.T) {
	pathStatsMap = make(map[string]*pathStatsInternal)

	internalPaths := []string{
		"/v1/login",
		"/v1/routes",
		"/v1/setup",
		"/metrics",
		"/healthz",
		"/readyz",
	}
	for _, path := range internalPaths {
		RecordPathRequest("example.com", path, 0.1, 100)
	}

	stats := GetPathStats(t.Context())
	if len(stats) != 0 {
		t.Errorf("expected 0 stats for internal paths, got %d", len(stats))
	}
}

func TestIsInternalAPIPath(t *testing.T) {
	cases := []struct {
		path     string
		internal bool
	}{
		{"/v1/login", true},
		{"/v1/routes", true},
		{"/v1/", true},
		{"/metrics", true},
		{"/healthz", true},
		{"/readyz", true},
		{"/api/users", false},
		{"/", false},
		{"/app", false},
		{"/v1", false}, // exact "/v1" without trailing slash is not internal
	}
	for _, tc := range cases {
		got := isInternalAPIPath(tc.path)
		if got != tc.internal {
			t.Errorf("isInternalAPIPath(%q) = %v, want %v", tc.path, got, tc.internal)
		}
	}
}
