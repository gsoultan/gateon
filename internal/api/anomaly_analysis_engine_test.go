package api

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestAnomalyAnalysisEngine_HeaderConsistency(t *testing.T) {
	engine := &AnomalyAnalysisEngine{}

	tests := []struct {
		name          string
		trace         telemetry.TraceRecord
		routes        []*gateonv1.Route
		expectAnomaly bool
	}{
		{
			name: "Valid Browser HTTP",
			trace: telemetry.TraceRecord{
				SourceIP:       "1.1.1.1",
				UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
				RequestHeaders: `{"Accept-Language":"en-US", "Accept-Encoding":"gzip", "Accept":"text/html"}`,
				ServiceName:    "route-http",
				Timestamp:      time.Now(),
			},
			routes: []*gateonv1.Route{
				{Id: "route-http", Type: "http"},
			},
			expectAnomaly: false,
		},
		{
			name: "Spoofed Browser HTTP (missing headers)",
			trace: telemetry.TraceRecord{
				SourceIP:       "1.1.1.2",
				UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36",
				RequestHeaders: `{}`,
				ServiceName:    "route-http",
				Timestamp:      time.Now(),
			},
			routes: []*gateonv1.Route{
				{Id: "route-http", Type: "http"},
			},
			expectAnomaly: true,
		},
		{
			name: "Valid gRPC Client",
			trace: telemetry.TraceRecord{
				SourceIP:       "1.1.1.3",
				UserAgent:      "grpc-go/1.40.0",
				RequestHeaders: `{"Content-Type":"application/grpc"}`,
				ServiceName:    "route-grpc",
				Timestamp:      time.Now(),
			},
			routes: []*gateonv1.Route{
				{Id: "route-grpc", Type: "grpc"},
			},
			expectAnomaly: false,
		},
		{
			name: "Mozilla UA on gRPC route (suspicious)",
			trace: telemetry.TraceRecord{
				SourceIP:       "1.1.1.4",
				UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				RequestHeaders: `{"Accept-Language":"en-US"}`,
				ServiceName:    "route-grpc",
				Timestamp:      time.Now(),
			},
			routes: []*gateonv1.Route{
				{Id: "route-grpc", Type: "grpc"},
			},
			expectAnomaly: true,
		},
		{
			name: "Mozilla UA with valid HTTP headers on gRPC route (suspicious)",
			trace: telemetry.TraceRecord{
				SourceIP:       "1.1.1.5",
				UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				RequestHeaders: `{"Accept-Language":"en-US", "Accept-Encoding":"gzip"}`,
				ServiceName:    "route-grpc",
				Timestamp:      time.Now(),
			},
			routes: []*gateonv1.Route{
				{Id: "route-grpc", Type: "grpc"},
			},
			expectAnomaly: true,
		},
		{
			name: "Mozilla UA with empty RequestHeaders (should not flag if debugger off)",
			trace: telemetry.TraceRecord{
				SourceIP:       "1.1.1.6",
				UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
				RequestHeaders: "",
				ServiceName:    "route-http",
				Timestamp:      time.Now(),
			},
			routes: []*gateonv1.Route{
				{Id: "route-http", Type: "http"},
			},
			expectAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &DiagnosticData{
				Traces: []telemetry.TraceRecord{tt.trace},
				Routes: tt.routes,
			}
			engine.Analyze(t.Context(), data)

			stats := data.IPStats[tt.trace.SourceIP]
			if stats == nil {
				t.Fatalf("stats for IP %s not found", tt.trace.SourceIP)
			}
			if (stats.HeaderAnomaly > 0) != tt.expectAnomaly {
				t.Errorf("expected anomaly %v, got %v (stats.HeaderAnomaly = %d)", tt.expectAnomaly, stats.HeaderAnomaly > 0, stats.HeaderAnomaly)
			}
		})
	}
}
