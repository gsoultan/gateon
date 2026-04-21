package api

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// DiagnosticData holds the data needed for anomaly detection.
type DiagnosticData struct {
	Traces          []telemetry.TraceRecord
	Routes          []*gateonv1.Route
	ManagementHosts []string
	IPStats         map[string]*IPStats
}

// IPStats holds aggregated metrics for a specific source IP.
type IPStats struct {
	TotalRequests int
	Error4xx      int
	Error401      int
	Error403      int
	Error404      int
	Error5xx      int
	TotalDuration float64
	LastSeen      time.Time
	UniquePaths   map[string]struct{}
	CountryCode   string
}

// AnomalyDetector defines the interface for different anomaly detection strategies.
type AnomalyDetector interface {
	Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly
}

func populateAnomalyGeo(a *gateonv1.Anomaly, countryCode string) {
	if countryCode == "" || countryCode == "XX" {
		return
	}
	a.CountryCode = countryCode
	lat, lon := telemetry.GetCountryCoordinates(countryCode)
	a.Latitude = lat
	a.Longitude = lon
}

// HackerAttackDetector detects potential hacker attacks like high frequency requests from a single IP.
type HackerAttackDetector struct{}

func (d *HackerAttackDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	for ip, stats := range data.IPStats {
		if stats.TotalRequests > 50 { // Lowered threshold for better visibility
			anomaly := &gateonv1.Anomaly{
				Type:           "high_traffic",
				Severity:       "medium",
				Description:    fmt.Sprintf("High request volume (%d requests) from IP %s", stats.TotalRequests, ip),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         ip,
				Recommendation: "Implement rate limiting for this IP or check if it is a legitimate crawler.",
			}
			populateAnomalyGeo(anomaly, stats.CountryCode)
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}

// UnlistedRouteDetector detects requests to routes not present in the configuration.
type UnlistedRouteDetector struct{}

func (d *UnlistedRouteDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	for _, tr := range data.Traces {
		if tr.ServiceName == "" || tr.ServiceName == "unknown" {
			anomaly := &gateonv1.Anomaly{
				Type:           "unlisted_route",
				Severity:       "medium",
				Description:    fmt.Sprintf("Request to unlisted route/host: %s", tr.Path),
				Timestamp:      tr.Timestamp.Format(time.RFC3339),
				Source:         tr.SourceIP,
				Recommendation: "Verify if this path should be registered in the proxy configuration or blocked.",
			}
			populateAnomalyGeo(anomaly, tr.CountryCode)
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}

// ManagementDomainDetector detects unauthorized access or anomalies related to the management domain.
type ManagementDomainDetector struct{}

func (d *ManagementDomainDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	if len(data.ManagementHosts) == 0 {
		return nil
	}

	for _, tr := range data.Traces {
		isMgmt := false
		for _, host := range data.ManagementHosts {
			if strings.Contains(tr.Path, host) {
				isMgmt = true
				break
			}
		}

		if isMgmt {
			// If it's a management request but not from an internal IP
			if !isInternalIP(tr.SourceIP) && tr.SourceIP != "127.0.0.1" && tr.SourceIP != "::1" && tr.SourceIP != "" {
				anomaly := &gateonv1.Anomaly{
					Type:           "management_access_violation",
					Severity:       "critical",
					Description:    fmt.Sprintf("External IP %s accessed management domain %s", tr.SourceIP, tr.Path),
					Timestamp:      tr.Timestamp.Format(time.RFC3339),
					Source:         tr.SourceIP,
					Recommendation: "Restrict management access to internal VPN or specific trusted IP addresses only.",
				}
				populateAnomalyGeo(anomaly, tr.CountryCode)
				anomalies = append(anomalies, anomaly)
			}
		}
	}
	return anomalies
}

func isInternalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

// BruteForceDetector detects high frequency of authentication failures.
type BruteForceDetector struct{}

func (d *BruteForceDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	for ip, stats := range data.IPStats {
		if stats.Error401+stats.Error403 > 5 {
			anomaly := &gateonv1.Anomaly{
				Type:           "brute_force_attempt",
				Severity:       "high",
				Description:    fmt.Sprintf("Multiple authentication failures (%d) from IP %s", stats.Error401+stats.Error403, ip),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         ip,
				Recommendation: "Investigate authentication logs and consider temporary IP blocking or account lockout.",
			}
			populateAnomalyGeo(anomaly, stats.CountryCode)
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}

// ScannerDetector detects directory traversal or resource scanning (many 404s).
type ScannerDetector struct{}

func (d *ScannerDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	for ip, stats := range data.IPStats {
		if stats.Error404 > 10 {
			anomaly := &gateonv1.Anomaly{
				Type:           "security_scan",
				Severity:       "medium",
				Description:    fmt.Sprintf("High volume of 404 errors (%d) from IP %s - possible scanning", stats.Error404, ip),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         ip,
				Recommendation: "Block this IP or implement a WAF to mitigate automated scanning tools.",
			}
			populateAnomalyGeo(anomaly, stats.CountryCode)
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
}

// SlowClientDetector detects potential resource exhaustion attempts or slow network issues.
type SlowClientDetector struct{}

func (d *SlowClientDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	for ip, stats := range data.IPStats {
		if stats.TotalRequests > 5 {
			avgLatency := stats.TotalDuration / float64(stats.TotalRequests)
			if avgLatency > 5000 { // > 5 seconds average
				anomaly := &gateonv1.Anomaly{
					Type:           "slow_client_anomaly",
					Severity:       "low",
					Description:    fmt.Sprintf("Abnormally high average latency (%.2fms) from IP %s", avgLatency, ip),
					Timestamp:      stats.LastSeen.Format(time.RFC3339),
					Source:         ip,
					Recommendation: "Check for network latency issues or potential Slowloris attack; adjust request timeouts.",
				}
				populateAnomalyGeo(anomaly, stats.CountryCode)
				anomalies = append(anomalies, anomaly)
			}
		}
	}
	return anomalies
}

// ShadowedRouteDetector identifies routes that are never reached because a more generic route has higher priority.
type ShadowedRouteDetector struct{}

func (d *ShadowedRouteDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	// Group routes by entrypoint
	epToRoutes := make(map[string][]*gateonv1.Route)
	for _, rt := range data.Routes {
		if rt.Disabled {
			continue
		}
		for _, epID := range rt.Entrypoints {
			epToRoutes[epID] = append(epToRoutes[epID], rt)
		}
	}

	for epID, routes := range epToRoutes {
		for i, r1 := range routes {
			for j, r2 := range routes {
				if i == j {
					continue
				}

				// If r1 has higher or equal priority and is more generic than r2
				if r1.Priority >= r2.Priority && isMoreGeneric(r1.Rule, r2.Rule) {
					anomalies = append(anomalies, &gateonv1.Anomaly{
						Type:           "shadowed_route",
						Severity:       "warning",
						Description:    fmt.Sprintf("Route '%s' (Priority %d) is shadowed by '%s' (Priority %d) on entrypoint %s", r2.Name, r2.Priority, r1.Name, r1.Priority, epID),
						Timestamp:      time.Now().Format(time.RFC3339),
						Source:         r2.Id,
						Recommendation: fmt.Sprintf("Increase priority of route '%s' or refine the rule for '%s' to avoid overlap.", r2.Name, r1.Name),
					})
					// Only report once per shadowed route
					break
				}
			}
		}
	}

	return anomalies
}

// isMoreGeneric is a simplified heuristic to check if rule1 shadows rule2.
// Real-world implementation would need a proper rule parser.
func isMoreGeneric(rule1, rule2 string) bool {
	if rule1 == rule2 {
		return true
	}

	// Heuristic: Host("example.com") shadows Host("example.com") && PathPrefix("/api")
	if strings.HasPrefix(rule2, rule1) && strings.Contains(rule2, "&&") {
		return true
	}

	// Heuristic: Host(`example.com`) shadows Host(`example.com`)
	r1Normalized := strings.ReplaceAll(rule1, "`", "\"")
	r2Normalized := strings.ReplaceAll(rule2, "`", "\"")

	if r1Normalized == r2Normalized {
		return true
	}

	// Check if rule1 is just a Host and rule2 is same Host with more conditions
	if strings.HasPrefix(r1Normalized, "Host(") && !strings.Contains(r1Normalized, "&&") {
		if strings.HasPrefix(r2Normalized, r1Normalized) && strings.Contains(r2Normalized, "&&") {
			return true
		}
	}

	return false
}

// AnomalyAnalysisEngine orchestrates different detectors.
type AnomalyAnalysisEngine struct {
	detectors []AnomalyDetector
}

func NewAnomalyAnalysisEngine() *AnomalyAnalysisEngine {
	return &AnomalyAnalysisEngine{
		detectors: []AnomalyDetector{
			&HackerAttackDetector{},
			&UnlistedRouteDetector{},
			&ManagementDomainDetector{},
			&BruteForceDetector{},
			&ScannerDetector{},
			&SlowClientDetector{},
			&ShadowedRouteDetector{},
		},
	}
}

func (e *AnomalyAnalysisEngine) Analyze(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	// Pre-process traces for performance - single pass
	data.IPStats = make(map[string]*IPStats)
	for _, tr := range data.Traces {
		if tr.SourceIP == "" {
			continue
		}
		stats, ok := data.IPStats[tr.SourceIP]
		if !ok {
			stats = &IPStats{
				UniquePaths: make(map[string]struct{}),
				CountryCode: tr.CountryCode,
			}
			data.IPStats[tr.SourceIP] = stats
		}
		stats.TotalRequests++
		stats.TotalDuration += tr.DurationMs
		if tr.Timestamp.After(stats.LastSeen) {
			stats.LastSeen = tr.Timestamp
		}
		stats.UniquePaths[tr.Path] = struct{}{}

		if strings.Contains(tr.Status, "401") {
			stats.Error401++
		} else if strings.Contains(tr.Status, "403") {
			stats.Error403++
		} else if strings.Contains(tr.Status, "404") {
			stats.Error404++
		} else if strings.HasPrefix(tr.Status, "4") {
			stats.Error4xx++
		} else if strings.HasPrefix(tr.Status, "5") {
			stats.Error5xx++
		}
	}

	var allAnomalies []*gateonv1.Anomaly
	for _, d := range e.detectors {
		allAnomalies = append(allAnomalies, d.Detect(ctx, data)...)
	}
	return allAnomalies
}
