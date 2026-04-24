package api

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
	// suspiciousPathRegex matches common sensitive files and directories.
	suspiciousPathRegex = regexp.MustCompile(`(?i)(\.env|\.git|\.htaccess|\.config|wp-admin|wp-login|phpinfo|/etc/passwd|win\.ini|cgi-bin|bin/sh|backup|db\.sql|config\.php|web-config|node_modules|169\.254\.169\.254|metadata\.google\.internal|\.aws/credentials|/etc/shadow|\.ssh/|/proc/self/|\.docker/config\.json|autoexec\.bat|web\.config)`)

	// sqlIPathRegex matches common SQL injection patterns.
	sqlIPathRegex = regexp.MustCompile(`(?i)(union\s+select|union\s+all\s+select|waitfor\s+delay|pg_sleep|sleep\(|benchmark\(|'(\s+)?or(\s+)?'1'(\s+)?=|--|;|\/\*|xp_cmdshell|information_schema|drop\s+table|truncate\s+table)`)

	// xssPathRegex matches common Cross-Site Scripting patterns.
	xssPathRegex = regexp.MustCompile(`(?i)(<script>|javascript:|onload=|onerror=|alert\(|prompt\(|confirm\(|eval\(|document\.cookie|window\.location|onmouseover=)`)

	// traversalPathRegex matches path traversal attempts.
	traversalPathRegex = regexp.MustCompile(`(?i)(\.\./|\.\.\\|/etc/|/var/log/|/windows/|/boot\.ini)`)

	// rcePathRegex matches Remote Code Execution patterns like Log4Shell or Shellshock.
	rcePathRegex = regexp.MustCompile(`(?i)(\$\{jndi:|()\s*\{\s*:\s*;\s*\}\s*;|base64\s*--decode|python\s+-c|perl\s+-e|php\s+-r|sh\s+-c|nc\s+-e|cmd\.exe|powershell\.exe)`)

	// suspiciousAgentRegex matches known security scanning tools and aggressive bots.
	suspiciousAgentRegex = regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirb|dirbuster|ffuf|hydra|burp|metasploit|w3af)`)

	// suspiciousRefererRegex matches suspicious referer headers.
	suspiciousRefererRegex = regexp.MustCompile(`(?i)(evil\.com|attacker|hacker|exploit|malicious|pwned)`)
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

	// Pre-pass for coordinated scan detection
	pathIPs := d.detectCoordinatedScans(data)

	// Pre-pass for multi-IP attacks via fingerprinting
	fingerprintAnomalies := d.detectMultiIPAttacks(data, threshold)
	anomalies = append(anomalies, fingerprintAnomalies...)

	for ip, stats := range data.IPStats {
		score := 0
		reasons := []string{}
		primaryType := "security_threat"

		// Associate fingerprint if available
		var fingerprint string
		for _, tr := range data.Traces {
			if tr.SourceIP == ip && tr.Fingerprint != "" {
				fingerprint = tr.Fingerprint
				break
			}
		}

		// 1. Traffic Volume & Bursts
		score += d.analyzeTraffic(stats, &reasons, &primaryType)

		// 2. Error Rates
		score += d.analyzeErrors(stats, &reasons, &primaryType)

		// 3. Pattern Matching (Paths, Queries, Payloads)
		score += d.analyzePatterns(stats, pathIPs, &reasons, &primaryType)

		// 4. Header Analysis (User-Agent, Referer)
		score += d.analyzeHeaders(stats, &reasons)

		// 5. Behavioral Patterns
		score += d.analyzeBehavior(stats, &reasons)

		if score >= int(threshold) {
			severity := d.calculateSeverity(score, threshold)

			anomaly := &gateonv1.Anomaly{
				Type:           primaryType,
				Severity:       severity,
				Description:    fmt.Sprintf("Potential security threat from IP %s: %s", ip, strings.Join(reasons, ", ")),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         ip,
				Recommendation: "Review IP activity, consider blocking via firewall or middleware, and check backend logs for exploitation attempts.",
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
			if suspiciousPathRegex.MatchString(lp) || traversalPathRegex.MatchString(lp) {
				if _, ok := pathIPs[lp]; !ok {
					pathIPs[lp] = make(map[string]struct{})
				}
				pathIPs[lp][ip] = struct{}{}
			}
		}
	}
	return pathIPs
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

	if stats.Error401+stats.Error403 > 10 {
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

	for path := range stats.UniquePaths {
		lp := strings.ToLower(path)
		pathMatched := false

		if suspiciousPathRegex.MatchString(lp) {
			score += 25
			pathMatched = true
			if len(pathIPs[lp]) > 1 {
				coordinatedCount++
			}
		}

		if sqlIPathRegex.MatchString(lp) {
			score += 40
			pathMatched = true
		}

		if xssPathRegex.MatchString(lp) {
			score += 35
			pathMatched = true
		}

		if traversalPathRegex.MatchString(lp) {
			score += 40
			pathMatched = true
		}

		if rcePathRegex.MatchString(lp) {
			score += 60
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
	agentMatched := false
	for agent := range stats.UserAgents {
		if suspiciousAgentRegex.MatchString(strings.ToLower(agent)) {
			score += 70
			agentMatched = true
			break
		}
	}
	if agentMatched {
		*reasons = append(*reasons, "Suspicious User-Agent detected (known scanning tool)")
	}

	refererMatched := false
	for ref := range stats.Referers {
		if suspiciousRefererRegex.MatchString(strings.ToLower(ref)) {
			score += 40
			refererMatched = true
			break
		}
	}
	if refererMatched {
		*reasons = append(*reasons, "Suspicious Referer header detected")
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
		if len(stats.IPs) > 3 { // Threshold for IP rotation detection
			anomaly := &gateonv1.Anomaly{
				Type:           "security_threat",
				Severity:       "high",
				Description:    fmt.Sprintf("Multi-IP attack detected via fingerprinting: actor rotated %d IPs for the same client profile", len(stats.IPs)),
				Timestamp:      stats.LastSeen.Format(time.RFC3339),
				Source:         fp, // Use fingerprint as source
				Recommendation: "This actor is rotating IPs to bypass rate limits. Consider blocking the entire fingerprint or implementing more aggressive bot challenges.",
			}
			anomalies = append(anomalies, anomaly)

			// Also record to threats table
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
