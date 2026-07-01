package api

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

var (
// External intelligence clients can be added here
)

// SecurityThreatDetector detects potential security threats based on multiple signals.
type SecurityThreatDetector struct {
	Threshold  float64
	Reputation *reputation.IPReputationStore
	Config     *gateonv1.BehavioralConfig
}

func (d *SecurityThreatDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	if d.Config != nil && !d.Config.Enabled {
		return nil
	}

	var anomalies []*gateonv1.Anomaly
	var mu sync.Mutex

	threshold := d.getAdaptiveThreshold(d.Threshold, data)

	// 1. Coordinated scan detection
	pathIPs := data.PathIPs
	totalIPs := len(data.IPStats)

	if d.Config == nil || d.Config.EnableSequenceValidation {
		mu.Lock()
		anomalies = append(anomalies, d.detectCoordinatedSequences(data)...)
		anomalies = append(anomalies, d.detectSharedBehavioralClusters(data)...)
		mu.Unlock()
	}

	// 2. Multi-IP attacks via fingerprinting
	mu.Lock()
	anomalies = append(anomalies, d.detectMultiIPAttacks(data, threshold)...)
	mu.Unlock()

	// 3. Impossible Travel detection
	if d.Config == nil || d.Config.EnableImpossibleTravel {
		mu.Lock()
		anomalies = append(anomalies, d.detectImpossibleTravel(data)...)
		mu.Unlock()
	}

	// 4. Per-IP analysis (Parallelized)
	var wg sync.WaitGroup
	for ip, stats := range data.IPStats {
		wg.Add(1)
		go func(ip string, stats *IPStats) {
			defer wg.Done()
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
			if stats.LastTrace != nil {
				fingerprint = stats.LastTrace.Fingerprint
			}

			// Analysis pipeline
			score += d.analyzeTraffic(stats, &reasons, &primaryType)
			score += d.analyzeErrors(stats, &reasons, &primaryType)
			score += d.analyzePatterns(stats, pathIPs, totalIPs, &reasons, &primaryType)
			score += d.analyzeHeaders(stats, &reasons)
			score += d.analyzeBehavior(stats, &reasons)
			score += d.analyzeDirectoryBusting(stats, &reasons)

			// External Threat Intelligence
			if d.Reputation != nil && (score > 0 || stats.TotalRequests > 10) {
				if abuseScore, provider := d.Reputation.GetExternalScore(ctx, ip); abuseScore > 20 {
					score += abuseScore / 2
					reasons = append(reasons, fmt.Sprintf("External threat feed (%s) confidence: %d%%", provider, abuseScore))
				}
			}

			if score >= int(threshold) {
				severity := d.calculateSeverity(score, threshold)
				mitigated := data.IsIPMitigated(ip)
				recommendation := d.getAdaptiveRecommendation(score, primaryType)

				anomaly := &gateonv1.Anomaly{
					Type:           primaryType,
					Severity:       severity,
					Description:    fmt.Sprintf("Potential security threat from IP %s: %s", ip, strings.Join(reasons, ", ")),
					Timestamp:      stats.LastSeen.Format(time.RFC3339),
					Source:         ip,
					Recommendation: recommendation,
					Mitigated:      mitigated,
					Score:          float64(score),
					Confidence:     math.Min(1.0, float64(score)/threshold),
				}
				populateAnomalyGeo(ctx, anomaly, ip)
				mu.Lock()
				anomalies = append(anomalies, anomaly)
				mu.Unlock()

				// Persist to security_threats table
				actionTaken := ""
				if mitigated {
					actionTaken = "blocked"
				}
				threat := telemetry.SecurityThreat{
					Type:        primaryType,
					SourceIP:    ip,
					Fingerprint: fingerprint,
					Score:       float64(score),
					Details:     strings.Join(reasons, "; "),
					Time:        stats.LastSeen,
					ActionTaken: actionTaken,
					Confidence:  math.Min(1.0, float64(score)/threshold),
				}

				if stats.LastTrace != nil {
					threat.RequestHeaders = stats.LastTrace.RequestHeaders
					threat.RequestBody = stats.LastTrace.RequestBody
					threat.ResponseHeaders = stats.LastTrace.ResponseHeaders
					threat.ResponseBody = stats.LastTrace.ResponseBody
					threat.UserAgent = stats.LastTrace.UserAgent
					threat.Method = stats.LastTrace.Method
					threat.RouteID = stats.LastTrace.RouteID
					threat.RequestURI = stats.LastTrace.Path
				}

				telemetry.RecordSecurityThreat(threat)
			}
		}(ip, stats)
	}
	wg.Wait()
	return anomalies
}

func (d *SecurityThreatDetector) detectCoordinatedScans(data *DiagnosticData) map[string]map[string]struct{} {
	return data.PathIPs
}

func (d *SecurityThreatDetector) detectCoordinatedSequences(data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	totalIPs := len(data.IPStats)
	pathPopularityStr := data.PathPopularity

	patterns := GetCompiledPatterns()

	// 3. Score and flag sequences using pre-aggregated data
	for sig, stats := range data.SequenceStats {
		ipCount := len(stats.IPs)

		// DYNAMIC MINIMUM THRESHOLD: Scales with total traffic volume
		minIPs := 3
		if totalIPs > 20 {
			minIPs = int(math.Max(3, float64(totalIPs)*0.06))
		}

		if ipCount < minIPs {
			continue
		}

		// ENTROPY ANALYSIS: More robust than simple ratios
		uaEntropy := d.calculateShannonEntropy(stats.UserAgents, stats.UACount)
		ja3Entropy := d.calculateShannonEntropy(stats.JA3s, stats.JA3Count)

		// POPULARITY ANALYSIS: Determine if this sequence is a "Happy Path"
		minPopularity := totalIPs
		for _, h := range sig {
			p, ok := data.PathMap[h]
			if !ok {
				continue
			}
			pop := pathPopularityStr[strings.ToLower(p)]
			if pop < minPopularity {
				minPopularity = pop
			}
		}
		popularityRatio := float64(minPopularity) / float64(max(1, totalIPs))

		// Base Score based on IP count
		score := float64(ipCount * 5)
		reasons := []string{fmt.Sprintf("%d distinct IPs", ipCount)}

		// SIGNAL: Low entropy means high concentration (botnet indicator)
		// Max entropy for UA would be around 4-5 bits in a diverse set.
		// Low diversity (e.g. all same UA) gives 0 entropy.
		if (stats.UACount >= 3 && uaEntropy < 0.5) || (stats.JA3Count >= 2 && ja3Entropy < 0.5) {
			score *= 2.5
			reasons = append(reasons, "extremely low identifier entropy (botnet cluster)")
		} else if uaEntropy > 2.0 && ja3Entropy > 1.5 {
			// High entropy -> likely legitimate diverse humans
			score *= 0.2
		}

		// SIGNAL: Sequence popularity (Happy Path discount)
		if totalIPs > 10 {
			if popularityRatio > 0.3 {
				score *= 0.1
				reasons = append(reasons, "common application flow")
			} else if popularityRatio > 0.15 {
				score *= 0.4
			}
		}

		// Suspicious paths in the sequence
		suspiciousInSig := false
		var sigPaths []string
		for _, h := range sig {
			p, ok := data.PathMap[h]
			if !ok {
				continue
			}
			sigPaths = append(sigPaths, p)
			lp := strings.ToLower(p)
			if patterns.SuspiciousPath.MatchString(lp) {
				suspiciousInSig = true
			}
			for _, hp := range patterns.HoneypotPaths {
				if lp == strings.ToLower(hp) {
					score += 200
					reasons = append(reasons, "contains honeypot path")
					break
				}
			}
		}

		if suspiciousInSig {
			score += 50
			reasons = append(reasons, "contains suspicious paths")
		}

		// Final detection threshold
		if score >= 100 || (ipCount > 25 && score >= 70) {
			ipList := slices.Collect(maps.Keys(stats.IPs))
			slices.Sort(ipList)
			sigStr := strings.Join(sigPaths, "->")

			anomaly := &gateonv1.Anomaly{
				Type:           "coordinated_attack",
				Severity:       d.calculateSeverity(int(score), 40),
				Description:    fmt.Sprintf("Coordinated cluster detected (%s): %d IPs followed sequence [%s]. UA Entropy: %.2f, Popularity: %.2f", strings.Join(reasons, ", "), ipCount, sigStr, uaEntropy, popularityRatio),
				Timestamp:      time.Now().Format(time.RFC3339),
				Source:         strings.Join(ipList, ", "),
				Recommendation: "Multiple actors with near-identical fingerprints are following an identical path sequence. High confidence of automated coordination.",
				Score:          score,
				Entropy:        uaEntropy,
				ClusterSize:    int32(ipCount),
				Confidence:     math.Min(1.0, score/150.0),
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (d *SecurityThreatDetector) calculateShannonEntropy(counts map[string]int, total int) float64 {
	if total <= 1 || len(counts) <= 1 {
		return 0
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func (d *SecurityThreatDetector) detectSharedBehavioralClusters(data *DiagnosticData) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	if len(data.IPStats) < 5 {
		return nil
	}

	// Group IPs by their path "signature"
	// Focus on IPs with significant activity
	signatures := make(map[string][]string)
	for ip, stats := range data.IPStats {
		if len(stats.UniquePaths) < 5 {
			continue
		}

		paths := slices.Collect(maps.Keys(stats.UniquePaths))
		slices.Sort(paths)

		// Use a subset if too many paths to keep signature stable
		if len(paths) > 15 {
			paths = paths[:15]
		}
		sig := strings.Join(paths, "|")
		signatures[sig] = append(signatures[sig], ip)
	}

	for sig, ips := range signatures {
		if len(ips) >= 4 {
			pathCount := strings.Count(sig, "|") + 1
			anomaly := &gateonv1.Anomaly{
				Type:           "coordinated_attack",
				Severity:       "high",
				Description:    fmt.Sprintf("Behavioral cluster detected: %d IPs shared identical set of %d paths. High confidence of distributed automated scanning.", len(ips), pathCount),
				Timestamp:      time.Now().Format(time.RFC3339),
				Source:         strings.Join(ips, ", "),
				Recommendation: "Identical path footprints across multiple IPs indicates a coordinated campaign. Recommend blocking the identified IP cluster.",
				Score:          100,
				ClusterSize:    int32(len(ips)),
				Confidence:     0.9,
			}
			anomalies = append(anomalies, anomaly)
		}
	}
	return anomalies
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

		for i := range len(list) - 1 {
			c1 := list[i]
			c2 := list[i+1]
			diff := c2.last.Sub(c1.last)
			if diff <= 0 {
				continue
			}

			// Cross-country check with distance
			if c1.code != c2.code && c1.code != "XX" && c2.code != "XX" {
				lat1, lon1 := telemetry.GetCountryCoordinates(c1.code)
				lat2, lon2 := telemetry.GetCountryCoordinates(c2.code)

				if lat1 != 0 || lon1 != 0 || lat2 != 0 || lon2 != 0 {
					dist := haversine(lat1, lon1, lat2, lon2)
					speed := dist / diff.Hours()

					// Commercial jet speed is ~900 km/h. Threshold at 1200 km/h to avoid false positives.
					if speed > 1200 {
						anomaly := &gateonv1.Anomaly{
							Type:           "security_threat",
							Severity:       "critical",
							Description:    fmt.Sprintf("Impossible travel detected for fingerprint %s: traveled %d km from %s to %s at %d km/h (within %s)", fp, int(dist), c1.code, c2.code, int(speed), diff.Round(time.Minute)),
							Timestamp:      c2.last.Format(time.RFC3339),
							Source:         fp,
							Recommendation: "This actor is accessing from geographically distant locations at physically impossible speeds, strongly indicating session hijacking or proxy-based automated attacks.",
						}
						anomalies = append(anomalies, anomaly)
					}
				} else if diff < 1*time.Hour {
					// Fallback for missing coordinates: any country change in < 1 hour is suspicious
					anomaly := &gateonv1.Anomaly{
						Type:           "security_threat",
						Severity:       "high",
						Description:    fmt.Sprintf("Impossible travel detected for fingerprint %s: seen in %s and then %s within %s", fp, c1.code, c2.code, diff.Round(time.Minute)),
						Timestamp:      c2.last.Format(time.RFC3339),
						Source:         fp,
						Recommendation: "Rapid geographical movement between countries detected.",
					}
					anomalies = append(anomalies, anomaly)
				}
			}
		}
	}
	return anomalies
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371 // Earth radius in km
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
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

func (d *SecurityThreatDetector) analyzePatterns(stats *IPStats, pathIPs map[string]map[string]struct{}, totalIPs int, reasons *[]string, primaryType *string) int {
	score := 0
	matches := 0
	coordinatedCount := 0
	honeypotHits := 0
	patterns := GetCompiledPatterns()

	for path := range stats.UniquePaths {
		lp := strings.ToLower(path)
		pathMatched := false

		// 1. Critical Path Weighting
		if weight, ok := patterns.CriticalPaths[lp]; ok {
			score += weight
		}

		// 2. Honeypot Check (Instant high-confidence hit)
		for _, hp := range patterns.HoneypotPaths {
			if lp == strings.ToLower(hp) {
				score += 200
				honeypotHits++
				pathMatched = true
				break
			}
		}

		// 3. Suspicious Path Check (e.g. .env, /etc/passwd)
		if patterns.SuspiciousPath.MatchString(lp) {
			pathMatched = true
			score += 30

			popRatio := float64(len(pathIPs[lp])) / float64(max(1, totalIPs))
			if (totalIPs < 10 || popRatio < 0.1) && len(pathIPs[lp]) > 1 {
				coordinatedCount++
			}
		}

		// 4. Combined Attack Pattern Fast-Pass (SQLi, XSS, RCE, etc.)
		if patterns.CombinedAttack.MatchString(lp) {
			score += 50
			pathMatched = true
		}

		if pathMatched {
			matches++
		}
	}

	if honeypotHits > 0 {
		*reasons = append(*reasons, fmt.Sprintf("Access to %d honeypot/trap paths detected (guaranteed bot/malicious actor)", honeypotHits))
		*primaryType = "honeypot_hit"
	}

	if matches > 0 && honeypotHits == 0 {
		*reasons = append(*reasons, fmt.Sprintf("Access to %d suspicious paths/payloads", matches))
		if *primaryType == "security_threat" {
			*primaryType = "security_scan"
		}
	}

	if coordinatedCount > 0 {
		score += int(math.Min(100, float64(20*coordinatedCount)))
		*reasons = append(*reasons, fmt.Sprintf("Coordinated access to %d suspicious paths", coordinatedCount))
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

	if stats.HeaderAnomaly > 5 {
		score += 30
		*reasons = append(*reasons, "Inconsistent HTTP headers for declared User-Agent (potential spoofing)")
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

	// IAT (Inter-Arrival Time) Regularity Analysis
	// Bots often have very low variance in their request timing.
	if stats.IATCount >= 10 {
		mean := stats.IATSum / float64(stats.IATCount)
		variance := (stats.IATSumSq / float64(stats.IATCount)) - (mean * mean)
		stdDev := math.Sqrt(math.Max(0, variance))

		// If standard deviation is extremely low relative to the mean, it's likely a bot.
		// Coefficient of Variation (CV) = StdDev / Mean
		if mean > 100 { // Only check for non-bursty traffic
			cv := stdDev / mean
			if cv < 0.05 { // Extremely regular timing (<5% variation)
				score += 60
				*reasons = append(*reasons, fmt.Sprintf("Highly regular request intervals (CV: %.3f)", cv))
			} else if cv < 0.15 {
				score += 25
				*reasons = append(*reasons, "Suspiciously regular request timing")
			}
		}
	}

	return score
}

func (d *SecurityThreatDetector) analyzeDirectoryBusting(stats *IPStats, reasons *[]string) int {
	// Require more 404s and a minimum total requests to avoid flagging low-traffic noise
	if stats.Error404 < 20 || stats.TotalRequests < 30 {
		return 0
	}

	// Group 404s by parent directory
	dirs := make(map[string]int)
	for path := range stats.UniquePaths {
		parts := strings.Split(path, "/")
		if len(parts) > 2 {
			dir := "/" + parts[1]
			dirs[dir]++
		}
	}

	maxBust := 0
	suspiciousDir := ""
	for dir, count := range dirs {
		if count > maxBust {
			maxBust = count
			suspiciousDir = dir
		}
	}

	// Higher threshold for modern apps
	if maxBust > 30 {
		*reasons = append(*reasons, fmt.Sprintf("Directory busting detected in %s (%d unique paths)", suspiciousDir, maxBust))
		return 60
	}

	return 0
}

func (d *SecurityThreatDetector) getAdaptiveThreshold(base float64, data *DiagnosticData) float64 {
	if base <= 0 {
		base = 30.0 // Higher default for modern traffic
	}
	totalIPs := len(data.IPStats)
	if totalIPs < 20 {
		return base
	}

	// Dynamic adjustment based on total traffic volume
	// Prevents false positives during high-traffic legitimate spikes
	trafficScale := math.Log10(float64(totalIPs))
	adaptiveBase := base * (1.0 + (trafficScale-1.3)*0.5) // 1.3 is log10(20)

	// Also consider global error rate
	totalReqs := 0
	totalErrors := 0
	for _, s := range data.IPStats {
		totalReqs += s.TotalRequests
		totalErrors += s.Error4xx + s.Error5xx
	}

	if totalReqs > 1000 {
		errorRate := float64(totalErrors) / float64(totalReqs)
		if errorRate > 0.1 {
			// If global error rate is high, system might be under attack or misconfigured
			// We increase threshold slightly to prioritize high-confidence threats
			adaptiveBase *= (1.0 + errorRate)
		}
	}

	return math.Min(150.0, adaptiveBase)
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

func (d *SecurityThreatDetector) getAdaptiveRecommendation(score int, primaryType string) string {
	if primaryType == "honeypot_hit" {
		return "IMMEDIATE ACTION REQUIRED: Client hit a decoy path. High confidence of automated malicious intent. Recommend immediate IP ban."
	}
	if score > 150 {
		return "CRITICAL THREAT: Multiple high-confidence attack signals. Recommend permanent blacklisting and audit of all recent requests from this actor."
	}
	switch primaryType {
	case "brute_force_attempt":
		return "MITIGATION: Potential credential stuffing or brute force. Implement progressive login delays, mandatory CAPTCHA, and notify affected users if applicable."
	case "security_scan":
		return "MITIGATION: Vulnerability scanning detected. Enable aggressive WAF rules and consider temporary IP throttling."
	case "reputation_hit":
		return "WARNING: IP has a known bad reputation in external databases. Monitor closely for suspicious payloads."
	case "high_traffic":
		return "ADAPTIVE: Unusual traffic volume. Apply rate limiting and check for potential L7 DDoS attempts."
	default:
		return "ADAPTIVE: Behavioral anomaly detected. Review logs and consider implementing a challenge (e.g., JS/Cookie challenge) to verify the client."
	}
}

func (d *SecurityThreatDetector) detectMultiIPAttacks(data *DiagnosticData, threshold float64) []*gateonv1.Anomaly {
	var anomalies []*gateonv1.Anomaly
	for fp, stats := range data.FingerprintStats {
		if len(stats.IPs) > 3 {
			mitigated := true
			for ip := range stats.IPs {
				if !data.IsIPMitigated(ip) {
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

			actionTaken := ""
			if mitigated {
				actionTaken = "blocked"
			}
			threat := telemetry.SecurityThreat{
				Type:        "security_threat",
				Fingerprint: fp,
				Score:       threshold + 10,
				Details:     fmt.Sprintf("Client fingerprint %s used across %d IPs", fp, len(stats.IPs)),
				Time:        stats.LastSeen,
				ActionTaken: actionTaken,
			}

			if stats.LastTrace != nil {
				threat.RequestHeaders = stats.LastTrace.RequestHeaders
				threat.RequestBody = stats.LastTrace.RequestBody
				threat.ResponseHeaders = stats.LastTrace.ResponseHeaders
				threat.ResponseBody = stats.LastTrace.ResponseBody
				threat.UserAgent = stats.LastTrace.UserAgent
				threat.Method = stats.LastTrace.Method
				threat.SourceIP = stats.LastTrace.SourceIP
				threat.RouteID = stats.LastTrace.RouteID
				threat.RequestURI = stats.LastTrace.Path
			}

			telemetry.RecordSecurityThreat(threat)
		}
	}
	return anomalies
}
