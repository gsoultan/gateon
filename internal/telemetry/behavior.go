package telemetry

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

const (
	maxSequenceLen = 10
	maxIATsLen     = 10
)

type BehaviorState struct {
	LastPath string
	LastTime time.Time
	Sequence []string
	IATs     []time.Duration
}

var (
	behaviorCache *lru.ARCCache
	behaviorMu    sync.Mutex
)

func init() {
	// Cache up to 10,000 unique fingerprints
	cache, _ := lru.NewARC(10000)
	behaviorCache = cache
}

// TrackBehavior analyzes sequences and timing of requests from a fingerprint.
func TrackBehavior(fingerprint string, r *http.Request) {
	if fingerprint == "" {
		return
	}

	behaviorMu.Lock()
	defer behaviorMu.Unlock()

	path := r.URL.Path
	now := time.Now()

	var state *BehaviorState
	if val, ok := behaviorCache.Get(fingerprint); ok {
		state = val.(*BehaviorState)
	} else {
		state = &BehaviorState{
			Sequence: make([]string, 0, maxSequenceLen),
			IATs:     make([]time.Duration, 0, maxIATsLen),
		}
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
			if isRoboticTiming(state.IATs) {
				RecordSecurityThreat(SecurityThreat{
					Type:        "behavioral_anomaly",
					Fingerprint: fingerprint,
					Score:       30,
					Details:     "Robotic timing pattern detected (highly regular intervals)",
					RequestURI:  path,
				})
			}
		}
	}

	// Update Sequence
	state.Sequence = append(state.Sequence, path)
	if len(state.Sequence) > maxSequenceLen {
		state.Sequence = state.Sequence[1:]
	}

	// Analyze Sequence for jump-to-critical-path
	if isSuspiciousSequence(state.Sequence) {
		RecordSecurityThreat(SecurityThreat{
			Type:        "behavioral_anomaly",
			Fingerprint: fingerprint,
			Score:       50,
			Details:     "Suspicious path sequence detected (jump to sensitive area)",
			RequestURI:  path,
		})
	}

	state.LastPath = path
	state.LastTime = now
	behaviorCache.Add(fingerprint, state)

	// Entropy-based DGA detection on Hostname
	hostname := r.Host
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	if isDGAPattern(hostname) {
		RecordSecurityThreat(SecurityThreat{
			Type:        "dga_detected",
			Fingerprint: fingerprint,
			Score:       40,
			Details:     "Potential DGA hostname detected: " + hostname,
			RequestURI:  path,
		})
	}
}

func isRoboticTiming(iats []time.Duration) bool {
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
		return cv < 0.1
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

	entropy := CalculateShannonEntropy(subdomain)
	// Randomly generated strings usually have higher entropy.
	// For English text it's usually 3.5-4.5. Random strings are often > 4.5.
	return entropy > 4.2
}

func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	invLen := 1.0 / float64(len(s))
	for _, count := range counts {
		p := float64(count) * invLen
		entropy -= p * math.Log2(p)
	}
	return entropy
}
