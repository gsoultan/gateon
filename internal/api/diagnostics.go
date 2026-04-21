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
	UserAgents    map[string]struct{}
	Methods       map[string]int
	Referers      map[string]int
	BurstCount    int // Requests in the peak 10-second window
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

// SecurityThreatDetector detects potential security threats based on multiple signals.
type SecurityThreatDetector struct {
	Threshold float64
}

func (d *SecurityThreatDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	threshold := d.Threshold
	if threshold <= 0 {
		threshold = 15.0 // Default
	}

	suspiciousPaths := []string{
		".env", ".git", ".htaccess", ".config", "wp-admin", "wp-login",
		"phpinfo", "/etc/passwd", "win.ini", "cgi-bin", "bin/sh", "backup",
		"db.sql", "config.php", "web-config", "node_modules",
	}

	suspiciousQueries := []string{
		"union select", "union all select", "waitfor delay", "pg_sleep",
		"<script>", "javascript:", "onload=", "onerror=", "../", "..\\",
	}

	suspiciousAgents := []string{
		"sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirb", "dirbuster",
	}

	suspiciousReferers := []string{
		"evil.com", "attacker", "hacker", "exploit",
	}

	// Pre-pass for coordinated scan detection
	pathIPs := make(map[string]map[string]struct{})
	for ip, stats := range data.IPStats {
		for path := range stats.UniquePaths {
			lp := strings.ToLower(path)
			isSuspicious := false
			for _, sp := range suspiciousPaths {
				if strings.Contains(lp, sp) {
					isSuspicious = true
					break
				}
			}
			if isSuspicious {
				if _, ok := pathIPs[lp]; !ok {
					pathIPs[lp] = make(map[string]struct{})
				}
				pathIPs[lp][ip] = struct{}{}
			}
		}
	}

	for ip, stats := range data.IPStats {
		score := 0
		reasons := []string{}
		primaryType := "security_threat"

		// 1. High request volume
		if stats.TotalRequests > 500 {
			score += 60
			reasons = append(reasons, fmt.Sprintf("Extremely high request volume (%d requests)", stats.TotalRequests))
			primaryType = "high_traffic"
		} else if stats.TotalRequests > 100 {
			score += 20
			reasons = append(reasons, "High request volume")
		}

		// 1b. Burst detection
		if stats.BurstCount > 30 {
			score += 50
			reasons = append(reasons, fmt.Sprintf("Request burst detected (%d requests in 10s)", stats.BurstCount))
		} else if stats.BurstCount > 10 {
			score += 15
		}

		// 2. High error rate
		errorRate := 0.0
		if stats.TotalRequests > 0 {
			errorRate = float64(stats.Error4xx+stats.Error5xx) / float64(stats.TotalRequests)
		}
		if errorRate > 0.7 && stats.TotalRequests > 10 {
			score += 40
			reasons = append(reasons, fmt.Sprintf("Very high error rate (%.1f%%)", errorRate*100))
		} else if errorRate > 0.3 && stats.TotalRequests > 10 {
			score += 15
		}

		// 3. Brute force patterns
		if stats.Error401+stats.Error403 > 10 {
			score += 50
			reasons = append(reasons, fmt.Sprintf("Multiple authentication failures (%d)", stats.Error401+stats.Error403))
			primaryType = "brute_force_attempt"
		}

		// 4. Scanning patterns
		if stats.Error404 > 15 {
			score += 40
			reasons = append(reasons, fmt.Sprintf("High volume of 404 errors (%d)", stats.Error404))
			if primaryType == "security_threat" {
				primaryType = "security_scan"
			}
		}

		// 5. Suspicious paths/payloads
		pathMatches := 0
		for path := range stats.UniquePaths {
			lp := strings.ToLower(path)
			isCoordinated := false
			for _, sp := range suspiciousPaths {
				if strings.Contains(lp, sp) {
					pathMatches++
					score += 25
					// Coordinated check
					if len(pathIPs[lp]) > 1 {
						isCoordinated = true
					}
					break
				}
			}
			if isCoordinated {
				score += 20
				reasons = append(reasons, fmt.Sprintf("Coordinated scan of suspicious path '%s' detected", lp))
			}

			for _, sq := range suspiciousQueries {
				if strings.Contains(lp, sq) {
					pathMatches++
					score += 35 // Increased
					break
				}
			}
		}
		if pathMatches > 0 {
			reasons = append(reasons, fmt.Sprintf("Access to %d suspicious paths/payloads", pathMatches))
			if primaryType == "security_threat" {
				primaryType = "security_scan"
			}
		}

		// 6. Suspicious User-Agents
		agentMatches := 0
		for agent := range stats.UserAgents {
			la := strings.ToLower(agent)
			for _, sa := range suspiciousAgents {
				if strings.Contains(la, sa) {
					agentMatches++
					score += 70 // Increased
					break
				}
			}
		}
		if agentMatches > 0 {
			reasons = append(reasons, "Suspicious User-Agent detected (known scanning tool)")
		}

		// 7. Referer analysis
		for ref := range stats.Referers {
			lr := strings.ToLower(ref)
			for _, sr := range suspiciousReferers {
				if strings.Contains(lr, sr) {
					score += 40
					reasons = append(reasons, "Suspicious Referer header detected")
					break
				}
			}
		}

		// 8. Adaptive: check if this IP's behavior is unusual compared to others
		// (Hard to do without full stats, but we can look for "only one method" if many requests)
		if stats.TotalRequests > 20 && len(stats.Methods) == 1 {
			if _, hasPost := stats.Methods["POST"]; hasPost {
				score += 20
				reasons = append(reasons, "Unusual POST-only traffic pattern")
			}
		}

		if score >= int(threshold) {
			severity := "low"
			if score >= int(threshold*4) {
				severity = "critical"
			} else if score >= int(threshold*2.5) {
				severity = "high"
			} else if score >= int(threshold*1.5) {
				severity = "medium"
			}

			anomaly := &gateonv1.Anomaly{
				Type:           primaryType,
				Severity:       severity,
				Description:    fmt.Sprintf("Potential security threat from IP %s: %s", ip, strings.Join(reasons, ", ")),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         ip,
				Recommendation: "Review IP activity, consider blocking via firewall or middleware, and check backend logs for exploitation attempts.",
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

func NewAnomalyAnalysisEngine(securityThreshold float64) *AnomalyAnalysisEngine {
	return &AnomalyAnalysisEngine{
		detectors: []AnomalyDetector{
			&SecurityThreatDetector{Threshold: securityThreshold},
			&UnlistedRouteDetector{},
			&ManagementDomainDetector{},
			&SlowClientDetector{},
			&ShadowedRouteDetector{},
		},
	}
}

func (e *AnomalyAnalysisEngine) Analyze(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	// Pre-process traces for performance - single pass
	data.IPStats = make(map[string]*IPStats)

	// For burst detection
	type ipTime struct {
		ip   string
		slot int64
	}
	burstTracker := make(map[ipTime]int)

	for _, tr := range data.Traces {
		if tr.SourceIP == "" {
			continue
		}
		stats, ok := data.IPStats[tr.SourceIP]
		if !ok {
			stats = &IPStats{
				UniquePaths: make(map[string]struct{}),
				UserAgents:  make(map[string]struct{}),
				Methods:     make(map[string]int),
				Referers:    make(map[string]int),
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
		if tr.UserAgent != "" {
			stats.UserAgents[tr.UserAgent] = struct{}{}
		}
		if tr.Method != "" {
			stats.Methods[tr.Method]++
		}
		if tr.Referer != "" {
			stats.Referers[tr.Referer]++
		}

		// Burst detection: 10-second slots
		slot := tr.Timestamp.Unix() / 10
		it := ipTime{tr.SourceIP, slot}
		burstTracker[it]++
		if burstTracker[it] > stats.BurstCount {
			stats.BurstCount = burstTracker[it]
		}

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
