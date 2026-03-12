package telemetry

import (
	"testing"
)

func TestPathStats(t *testing.T) {
	// Reset stats for test
	pathStatsMap = make(map[string]*pathStatsInternal)

	RecordPathRequest("example.com", "/api", 0.1)
	RecordPathRequest("example.com", "/api", 0.2)
	RecordPathRequest("other.com", "/", 0.5)

	stats := GetPathStats()
	if len(stats) != 2 {
		t.Errorf("expected 2 stats, got %d", len(stats))
	}

	for _, s := range stats {
		if s.Host == "example.com" && s.Path == "/api" {
			if s.RequestCount != 2 {
				t.Errorf("expected 2 requests for example.com/api, got %d", s.RequestCount)
			}
			if s.AvgLatency != 0.15 {
				t.Errorf("expected 0.15 avg latency for example.com/api, got %f", s.AvgLatency)
			}
		} else if s.Host == "other.com" && s.Path == "/" {
			if s.RequestCount != 1 {
				t.Errorf("expected 1 request for other.com/, got %d", s.RequestCount)
			}
			if s.AvgLatency != 0.5 {
				t.Errorf("expected 0.5 avg latency for other.com/, got %f", s.AvgLatency)
			}
		}
	}
}
