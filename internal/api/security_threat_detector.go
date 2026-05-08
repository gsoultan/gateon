package api

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
// External intelligence clients can be added here
)

// SecurityThreatDetector detects potential security threats based on multiple signals.
type SecurityThreatDetector struct {
	Threshold    float64
	ThreatClient *AbuseIPDBClient
	Reputation   *IPReputationStore
}

func (d *SecurityThreatDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly

	threshold := d.Threshold
	if threshold <= 0 {
		threshold = 15.0 // Default
	}

	// 1. Coordinated scan detection
	pathIPs := d.detectCoordinatedScans(data)

	// 2. Multi-IP attacks via fingerprinting
	anomalies = append(anomalies, d.detectMultiIPAttacks(data, threshold)...)

	// 3. Impossible Travel detection
	anomalies = append(anomalies, d.detectImpossibleTravel(data)...)

	// 4. Per-IP analysis
	for ip, stats := range data.IPStats {
		score := 0
		reasons := []string{}
		primaryType := "security_threat"

		// Check IP Reputation
		if d.Reputation != nil {
			if bad, repScore := d.Reputation.IsBad(ip); bad {
				score += int(repScore * 50)
				reasons = append(reasons, fmt.Sprintf("IP has bad reputation (score: %.2f)", repScore))
				primaryType = "reputation_hit"
			}
		}

		// Associate fingerprint if available
		var fingerprint string
		for _, tr := range data.Traces {
			if tr.SourceIP == ip && tr.Fingerprint != "" {
				fingerprint = tr.Fingerprint
				break
			}
		}

		// Analysis pipeline
		score += d.analyzeTraffic(stats, &reasons, &primaryType)
		score += d.analyzeErrors(stats, &reasons, &primaryType)
		score += d.analyzePatterns(stats, pathIPs, &reasons, &primaryType)
		score += d.analyzeHeaders(stats, &reasons)
		score += d.analyzeBehavior(stats, &reasons)

		// External Threat Intelligence
		if d.ThreatClient != nil && (score > 0 || stats.TotalRequests > 10) {
			if abuseScore, err := d.ThreatClient.CheckIP(ctx, ip); err == nil && abuseScore > 20 {
				score += abuseScore / 2
				reasons = append(reasons, fmt.Sprintf("External threat feed (AbuseIPDB) confidence: %d%%", abuseScore))
			}
		}

		if score >= int(threshold) {
			severity := d.calculateSeverity(score, threshold)
			mitigated := d.isIPBlocked(ip, data.Middlewares)

			anomaly := &gateonv1.Anomaly{
				Type:           primaryType,
				Severity:       severity,
				Description:    fmt.Sprintf("Potential security threat from IP %s: %s", ip, strings.Join(reasons, ", ")),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         ip,
				Recommendation: "Review IP activity, consider blocking via firewall or middleware, and check backend logs for exploitation attempts.",
				Mitigated:      mitigated,
			}
			populateAnomalyGeo(anomaly, ip)
			anomalies = append(anomalies, anomaly)

			// Persist to security_threats table
			telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
				Type:        primaryType,
				SourceIP:    ip,
				Fingerprint: fingerprint,
				Score:       float64(score),
				Details:     strings.Join(reasons, "; "),
				Time:        stats.LastSeen,
			})
		}
	}
	return anomalies
}

func (d *SecurityThreatDetector) detectCoordinatedScans(data *DiagnosticData) map[string]map[string]struct{} {
	pathIPs := make(map[string]map[string]struct{})
	for ip, stats := range data.IPStats {
		for path := range stats.UniquePaths {
			lp := strings.ToLower(path)
			if _, ok := pathIPs[lp]; !ok {
				pathIPs[lp] = make(map[string]struct{})
			}
			pathIPs[lp][ip] = struct{}{}
		}
	}
	return pathIPs
}

func (d *SecurityThreatDetector) detectImpossibleTravel(data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	for fp, stats := range data.FingerprintStats {
		if len(stats.Countries) < 2 {
			continue
		}

		// Sort countries by last seen time
		type countryTime struct {
			code string
			last time.Time
		}
		var list []countryTime
		for code, last := range stats.Countries {
			list = append(list, countryTime{code, last})
		}
		slices.SortFunc(list, func(a, b countryTime) int {
			return cmp.Compare(a.last.Unix(), b.last.Unix())
		})

		for i := 0; i < len(list)-1; i++ {
			c1 := list[i]
			c2 := list[i+1]
			diff := c2.last.Sub(c1.last)
			if diff < 2*time.Hour { // Cross-country in less than 2 hours is suspicious
				anomaly := &gateonv1.Anomaly{
					Type:           "security_threat",
					Severity:       "high",
					Description:    fmt.Sprintf("Impossible travel detected for fingerprint %s: seen in %s and then %s within %s", fp, c1.code, c2.code, diff.Round(time.Minute)),
					Timestamp:      c2.last.Format(time.RFC3339),
					Source:         fp,
					Recommendation: "This actor is accessing from multiple geographical locations rapidly, indicating session hijacking or credential sharing.",
				}
				anomalies = append(anomalies, anomaly)
			}
		}
	}
	return anomalies
}

func (d *SecurityThreatDetector) analyzeTraffic(stats *IPStats, reasons *[]string, primaryType *string) int {
	score := 0
	if stats.TotalRequests > 500 {
		score += 60
		*reasons = append(*reasons, fmt.Sprintf("Extremely high request volume (%d requests)", stats.TotalRequests))
		*primaryType = "high_traffic"
	} else if stats.TotalRequests > 100 {
		score += 20
		*reasons = append(*reasons, "High request volume")
	}

	if stats.BurstCount > 30 {
		score += 50
		*reasons = append(*reasons, fmt.Sprintf("Request burst detected (%d requests in 10s)", stats.BurstCount))
	} else if stats.BurstCount > 10 {
		score += 15
	}
	return score
}

func (d *SecurityThreatDetector) analyzeErrors(stats *IPStats, reasons *[]string, primaryType *string) int {
	score := 0
	errorRate := 0.0
	if stats.TotalRequests > 0 {
		errorRate = float64(stats.Error4xx+stats.Error5xx) / float64(stats.TotalRequests)
	}

	if errorRate > 0.7 && stats.TotalRequests > 10 {
		score += 40
		*reasons = append(*reasons, fmt.Sprintf("Very high error rate (%.1f%%)", errorRate*100))
	} else if errorRate > 0.3 && stats.TotalRequests > 10 {
		score += 15
	}

	// Advanced Auth Failure Detection
	loginPaths := []string{"/login", "/auth", "/signin", "/api/v1/auth", "/api/auth"}
	loginFailures := 0
	for _, p := range loginPaths {
		if count, ok := stats.PathErrors[p]; ok {
			loginFailures += count
		}
	}

	if loginFailures > 5 {
		score += 60
		*reasons = append(*reasons, fmt.Sprintf("Targeted brute force on auth endpoints (%d failures)", loginFailures))
		*primaryType = "brute_force_attempt"
	} else if stats.Error401+stats.Error403 > 10 {
		score += 50
		*reasons = append(*reasons, fmt.Sprintf("Multiple authentication failures (%d)", stats.Error401+stats.Error403))
		*primaryType = "brute_force_attempt"
	}

	if stats.Error404 > 15 {
		score += 40
		*reasons = append(*reasons, fmt.Sprintf("High volume of 404 errors (%d)", stats.Error404))
		if *primaryType == "security_threat" {
			*primaryType = "security_scan"
		}
	}
	return score
}

func (d *SecurityThreatDetector) analyzePatterns(stats *IPStats, pathIPs map[string]map[string]struct{}, reasons *[]string, primaryType *string) int {
	score := 0
	matches := 0
	coordinatedCount := 0
	patterns := GetCompiledPatterns()

	for path := range stats.UniquePaths {
		lp := strings.ToLower(path)
		pathMatched := false

		if patterns.SuspiciousPath.MatchString(lp) {
			score += 25
			pathMatched = true
			if len(pathIPs[lp]) > 1 {
				coordinatedCount++
			}
		}

		if patterns.SQLI.MatchString(lp) || patterns.XSS.MatchString(lp) || patterns.Traversal.MatchString(lp) ||
			patterns.RCE.MatchString(lp) || patterns.SSRF.MatchString(lp) || patterns.NoSQLI.MatchString(lp) ||
			patterns.CommandInjection.MatchString(lp) || patterns.ProtoPollution.MatchString(lp) {
			score += 40
			pathMatched = true
		}

		if pathMatched {
			matches++
		}
	}

	if matches > 0 {
		*reasons = append(*reasons, fmt.Sprintf("Access to %d suspicious paths/payloads", matches))
		if *primaryType == "security_threat" {
			*primaryType = "security_scan"
		}
	}

	if coordinatedCount > 0 {
		score += 20 * coordinatedCount
		*reasons = append(*reasons, fmt.Sprintf("Coordinated scan of %d suspicious paths detected", coordinatedCount))
	}

	return score
}

func (d *SecurityThreatDetector) analyzeHeaders(stats *IPStats, reasons *[]string) int {
	score := 0
	patterns := GetCompiledPatterns()

	for agent := range stats.UserAgents {
		if patterns.SuspiciousAgent.MatchString(strings.ToLower(agent)) {
			score += 70
			*reasons = append(*reasons, "Suspicious User-Agent detected (known scanning tool)")
			break
		}
	}

	for ref := range stats.Referers {
		if patterns.SuspiciousReferer.MatchString(strings.ToLower(ref)) {
			score += 40
			*reasons = append(*reasons, "Suspicious Referer header detected")
			break
		}
	}

	if len(stats.JA3s) > 1 {
		score += 30
		*reasons = append(*reasons, fmt.Sprintf("Multiple TLS fingerprints (JA3: %d) from single IP", len(stats.JA3s)))
	}

	if len(stats.JA4s) > 1 {
		score += 40
		*reasons = append(*reasons, fmt.Sprintf("Multiple TLS fingerprints (JA4+: %d) from single IP", len(stats.JA4s)))
	}

	return score
}

func (d *SecurityThreatDetector) analyzeBehavior(stats *IPStats, reasons *[]string) int {
	score := 0
	if stats.TotalRequests > 20 && len(stats.Methods) == 1 {
		if _, hasPost := stats.Methods["POST"]; hasPost {
			score += 20
			*reasons = append(*reasons, "Unusual POST-only traffic pattern")
		}
	}
	return score
}

func (d *SecurityThreatDetector) isIPBlocked(ip string, middlewares []*gateonv1.Middleware) bool {
	for _, mw := range middlewares {
		if mw.Type == "ipfilter" {
			if denyList, ok := mw.Config["deny_list"]; ok {
				ips := strings.Split(denyList, ",")
				for _, blockedIP := range ips {
					if strings.TrimSpace(blockedIP) == ip {
						return true
					}
				}
			}
		}
	}
	return false
}

func (d *SecurityThreatDetector) calculateSeverity(score int, threshold float64) string {
	if score >= int(threshold*4) {
		return "critical"
	} else if score >= int(threshold*2.5) {
		return "high"
	} else if score >= int(threshold*1.5) {
		return "medium"
	}
	return "low"
}

func (d *SecurityThreatDetector) detectMultiIPAttacks(data *DiagnosticData, threshold float64) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	for fp, stats := range data.FingerprintStats {
		if len(stats.IPs) > 3 {
			mitigated := true
			for ip := range stats.IPs {
				if !d.isIPBlocked(ip, data.Middlewares) {
					mitigated = false
					break
				}
			}

			anomaly := &gateonv1.Anomaly{
				Type:           "security_threat",
				Severity:       "high",
				Description:    fmt.Sprintf("Multi-IP attack detected via fingerprinting: actor rotated %d IPs for the same client profile", len(stats.IPs)),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         fp,
				Recommendation: "This actor is rotating IPs to bypass rate limits. Consider blocking the entire fingerprint or implementing more aggressive bot challenges.",
				Mitigated:      mitigated,
			}
			anomalies = append(anomalies, anomaly)

			telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
				Type:        "security_threat",
				Fingerprint: fp,
				Score:       threshold + 10,
				Details:     fmt.Sprintf("Client fingerprint %s used across %d IPs", fp, len(stats.IPs)),
				Time:        stats.LastSeen,
			})
		}
	}
	return anomalies
}
