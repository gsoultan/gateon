package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// SlowClientDetector detects potential resource exhaustion attempts or slow network issues.
type SlowClientDetector struct{}

func (d *SlowClientDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	for ip, stats := range data.IPStats {
		if stats.TotalRequests > 5 {
			avgLatency := stats.TotalDuration / float64(stats.TotalRequests)
			if avgLatency > 5000 { // > 5 seconds average
				mitigated := false
				// Check if IP is already blocked in middlewares
				for _, mw := range data.Middlewares {
					if mw.Type == "ipfilter" {
						if denyList, ok := mw.Config["deny_list"]; ok {
							ips := strings.Split(denyList, ",")
							for _, blockedIP := range ips {
								if strings.TrimSpace(blockedIP) == ip {
									mitigated = true
									break
								}
							}
						}
					}
					if mitigated {
						break
					}
				}

				anomaly := &gateonv1.Anomaly{
					Type:           "slow_client_anomaly",
					Severity:       "low",
					Description:    fmt.Sprintf("Abnormally high average latency (%.2fms) from IP %s", avgLatency, ip),
					Timestamp:      stats.LastSeen.Format(time.RFC3339),
					Source:         ip,
					Recommendation: "Check for network latency issues or potential Slowloris attack; adjust request timeouts.",
					Mitigated:      mitigated,
				}
				populateAnomalyGeo(anomaly, ip)
				anomalies = append(anomalies, anomaly)
			}
		}
	}
	return anomalies
}
