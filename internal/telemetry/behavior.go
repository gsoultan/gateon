package telemetry

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/security/entropy"
	lru "github.com/hashicorp/golang-lru"
)

const (
	maxSequenceLen = 10
	maxIATsLen     = 10
	behaviorShards = 16
)

type BehaviorState struct {
	LastPath    string
	LastTime    time.Time
	Sequence    []string
	IATs        []time.Duration
	StatusCodes []int
}

type behaviorShard struct {
	cache *lru.ARCCache
	mu    sync.Mutex
}

var (
	shards []*behaviorShard
)

func init() {
	size := cacheSizeFromEnv(envBehaviorCacheSize, cacheNameBehavior, defaultBehaviorCacheSize)
	perShard := max(size/behaviorShards, 1)
	shards = make([]*behaviorShard, behaviorShards)
	for i := range behaviorShards {
		cache, _ := lru.NewARC(perShard)
		shards[i] = &behaviorShard{
			cache: cache,
		}
	}
}

func getShard(fingerprint string) *behaviorShard {
	var hash uint32 = 2166136261
	for i := range len(fingerprint) {
		hash ^= uint32(fingerprint[i])
		hash *= 16777619
	}
	return shards[hash%behaviorShards]
}

// TrackBehavior analyzes sequences and timing of requests from a fingerprint.
func TrackBehavior(fingerprint string, r *http.Request, status int) {
	if fingerprint == "" {
		return
	}

	shard := getShard(fingerprint)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	path := r.URL.Path
	now := time.Now()

	var state *BehaviorState
	if val, ok := shard.cache.Get(fingerprint); ok {
		state = val.(*BehaviorState)
	} else {
		state = &BehaviorState{
			Sequence:    make([]string, 0, maxSequenceLen),
			IATs:        make([]time.Duration, 0, maxIATsLen),
			StatusCodes: make([]int, 0, maxSequenceLen),
		}
	}

	// Get global QPS to adjust sensitivity
	agg := GetAggregator()
	qps := agg.GetCachedQPS()
	// highTrafficFactor reduces sensitivity when QPS is high (e.g. > 1000)
	highTrafficFactor := 1.0
	if qps > 1000 {
		highTrafficFactor = 1.0 + (qps-1000)/1000.0
	}

	// Calculate IAT
	if !state.LastTime.IsZero() {
		iat := now.Sub(state.LastTime)
		state.IATs = append(state.IATs, iat)
		if len(state.IATs) > maxIATsLen {
			state.IATs = state.IATs[1:]
		}

		// Analyze IAT for robotic regularity (low variance)
		if len(state.IATs) >= 5 {
			if isRoboticTiming(state.IATs, highTrafficFactor) {
				RecordSecurityThreat(RecordSecurityThreatWithJA4(r, SecurityThreat{
					Type:        "behavioral_anomaly",
					Fingerprint: fingerprint,
					Score:       30 / highTrafficFactor,
					Details:     "Robotic timing pattern detected (highly regular intervals)",
					RequestURI:  path,
					ActionTaken: "flagged",
					Severity:    "low",
				}))
			}
			if isHeartbeatPattern(state.IATs, highTrafficFactor) {
				RecordSecurityThreat(RecordSecurityThreatWithJA4(r, SecurityThreat{
					Type:        "behavioral_anomaly",
					Fingerprint: fingerprint,
					Score:       40 / highTrafficFactor,
					Details:     "Heartbeat pattern detected (regular long-interval polling)",
					RequestURI:  path,
					ActionTaken: "flagged",
					Severity:    "medium",
				}))
			}
		}
	}

	// Update Sequence and Status
	state.Sequence = append(state.Sequence, path)
	if len(state.Sequence) > maxSequenceLen {
		state.Sequence = state.Sequence[1:]
	}
	state.StatusCodes = append(state.StatusCodes, status)
	if len(state.StatusCodes) > maxSequenceLen {
		state.StatusCodes = state.StatusCodes[1:]
	}

	// Analyze for API Fuzzing / Scanning
	if isFuzzing(state.StatusCodes, highTrafficFactor) {
		RecordSecurityThreat(RecordSecurityThreatWithJA4(r, SecurityThreat{
			Type:        "api_fuzzing",
			Fingerprint: fingerprint,
			Score:       60 / highTrafficFactor,
			Details:     "High rate of 404/403 responses detected (potential fuzzing/scanning)",
			RequestURI:  path,
			ActionTaken: "flagged",
			Severity:    "high",
		}))
	}

	// Analyze Sequence for jump-to-critical-path
	if isSuspiciousSequence(state.Sequence) {
		RecordSecurityThreat(RecordSecurityThreatWithJA4(r, SecurityThreat{
			Type:        "behavioral_anomaly",
			Fingerprint: fingerprint,
			Score:       50,
			Details:     "Suspicious path sequence detected (jump to sensitive area)",
			RequestURI:  path,
			ActionTaken: "flagged",
			Severity:    "medium",
		}))
	}

	// Analyze for Directory Traversal / Probe
	if isProbePattern(path) {
		RecordSecurityThreat(RecordSecurityThreatWithJA4(r, SecurityThreat{
			Type:        "probe_detected",
			Fingerprint: fingerprint,
			Score:       70,
			Details:     "Known exploit probe or directory traversal attempt: " + path,
			RequestURI:  path,
			ActionTaken: "flagged",
			Severity:    "high",
		}))
	}

	state.LastPath = path
	state.LastTime = now
	shard.cache.Add(fingerprint, state)

	// Entropy-based DGA detection on Hostname
	hostname := r.Host
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	if isDGAPattern(hostname) {
		RecordSecurityThreat(RecordSecurityThreatWithJA4(r, SecurityThreat{
			Type:        "dga_detected",
			Fingerprint: fingerprint,
			Score:       40,
			Details:     "Potential DGA hostname detected: " + hostname,
			RequestURI:  path,
			ActionTaken: "flagged",
		}))
	}
}

func isRoboticTiming(iats []time.Duration, factor float64) bool {
	if len(iats) < 2 {
		return false
	}
	var sum float64
	for _, iat := range iats {
		sum += iat.Seconds()
	}
	mean := sum / float64(len(iats))

	var variance float64
	for _, iat := range iats {
		diff := iat.Seconds() - mean
		variance += diff * diff
	}
	variance /= float64(len(iats))
	stdDev := math.Sqrt(variance)

	// Coefficient of variation (CV = stdDev / mean)
	// Real human traffic usually has CV > 0.5. Bots/Scripts often have CV < 0.1.
	if mean > 0 {
		cv := stdDev / mean
		// Reduce sensitivity under high traffic by lowering the CV threshold
		return cv < (0.1 / factor)
	}
	return false
}

func isHeartbeatPattern(iats []time.Duration, factor float64) bool {
	if len(iats) < 8 {
		return false
	}
	// Check for consistent long-interval requests (e.g., every 30s or 60s)
	// We look for low variance but higher mean than "bursty" robotic traffic.
	var sum float64
	for _, iat := range iats {
		sum += iat.Seconds()
	}
	mean := sum / float64(len(iats))

	if mean < 5.0 { // Heartbeats are usually slower than 5s
		return false
	}

	var variance float64
	for _, iat := range iats {
		diff := iat.Seconds() - mean
		variance += diff * diff
	}
	variance /= float64(len(iats))
	stdDev := math.Sqrt(variance)

	if mean > 0 {
		cv := stdDev / mean
		// Very low CV (< 0.05) on slow requests is a strong indicator of a scheduled task/script
		return cv < (0.05 / factor)
	}
	return false
}

func isFuzzing(codes []int, factor float64) bool {
	if len(codes) < 5 {
		return false
	}
	badCount := 0
	for _, c := range codes {
		if c == 404 || c == 403 || c == 401 {
			badCount++
		}
	}
	// If more than 60% of recent requests are errors, it's likely fuzzing.
	// We increase the required threshold under high traffic to avoid false positives from broken clients.
	threshold := 0.6 * factor
	if threshold > 0.95 {
		threshold = 0.95
	}
	return float64(badCount)/float64(len(codes)) > threshold
}

func isProbePattern(path string) bool {
	path = strings.ToLower(path)
	probes := []string{
		"../", "/etc/passwd", "/.git", "/.env", "/.ssh",
		"wp-admin", "wp-login", "wp-content",
		"phpmyadmin", "config.php", "web.config",
		"autodiscover.xml", "owa", ".aws/credentials",
		".well-known/security.txt", // sometimes probes look for this to find vuln disclosure info
	}
	for _, p := range probes {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

func isSuspiciousSequence(seq []string) bool {
	if len(seq) < 2 {
		return false
	}
	last := seq[len(seq)-1]

	// Sensitive paths that shouldn't be accessed without some preceding steps
	sensitivePrefixes := []string{"/api/v1/admin", "/config", "/backup", "/export", "/debug"}

	isSensitive := false
	for _, p := range sensitivePrefixes {
		if strings.HasPrefix(last, p) {
			isSensitive = true
			break
		}
	}

	if !isSensitive {
		return false
	}

	// If the previous paths don't include a "normal" entry point like / or /login or /dashboard
	hasEntry := false
	for i := range len(seq) - 1 {
		p := seq[i]
		if p == "/" || strings.HasPrefix(p, "/login") || strings.HasPrefix(p, "/dashboard") || strings.HasPrefix(p, "/ui") {
			hasEntry = true
			break
		}
	}

	return !hasEntry
}

func isDGAPattern(hostname string) bool {
	// Only check the subdomain part
	parts := strings.Split(hostname, ".")
	if len(parts) < 3 {
		return false
	}
	subdomain := parts[0]
	if len(subdomain) < 10 {
		return false
	}

	entropyScore := entropy.CalculateString(subdomain)
	// Randomly generated strings usually have higher entropy.
	// For English text it's usually 3.5-4.5. Random strings are often > 4.5.
	return entropyScore > 4.2
}
