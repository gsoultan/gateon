package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

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
