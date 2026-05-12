package telemetry

import (
	"math"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

// GetFingerprint returns a unique identifier for the client (JA3/JA4 or source IP).
func GetFingerprint(r *http.Request) string {
	// Simple IP extraction
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = strings.Split(xff, ",")[0]
	} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip = xri
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}

type Reputation struct {
	Score          float64
	LastEvent      time.Time
	ViolationCount int
	RecoveryRate   float64  // Points recovered per hour
	History        []string // Brief history of violation types
}

var (
	reputationCache *lru.ARCCache
	repMu           sync.RWMutex
)

func init() {
	cache, _ := lru.NewARC(100000)
	reputationCache = cache
}

// GetReputation returns the current reputation score for a fingerprint.
// Score starts at 100 (perfect). Decreases as threats are recorded.
func GetReputation(fingerprint string) float64 {
	if fingerprint == "" {
		return 50 // Unknown
	}
	repMu.Lock()
	defer repMu.Unlock()

	if val, ok := reputationCache.Get(fingerprint); ok {
		r := val.(*Reputation)
		// Gradually recover reputation over time.
		// Base rate is 1.0, but decreases as violations increase (adaptive recovery).
		rate := r.RecoveryRate
		if rate <= 0 {
			rate = 1.0
		}

		elapsed := time.Since(r.LastEvent).Hours()
		if elapsed > 1 {
			r.Score = math.Min(100, r.Score+(elapsed*rate))
		}
		return r.Score
	}
	return 100
}

// DecreaseReputation reduces the score based on threat severity.
// GetReputationScore returns the current score for a fingerprint.
func GetReputationScore(fingerprint string) float64 {
	if fingerprint == "" {
		return 100.0
	}
	repMu.RLock()
	defer repMu.RUnlock()
	if val, ok := reputationCache.Get(fingerprint); ok {
		return val.(*Reputation).Score
	}
	return 100.0
}

func DecreaseReputation(fingerprint string, penalty float64, reason string) {
	if fingerprint == "" {
		return
	}
	repMu.Lock()
	defer repMu.Unlock()

	var r *Reputation
	if val, ok := reputationCache.Get(fingerprint); ok {
		r = val.(*Reputation)
	} else {
		r = &Reputation{Score: 100, ViolationCount: 0, RecoveryRate: 1.0, History: []string{}}
	}

	r.ViolationCount++
	if reason != "" {
		r.History = append(r.History, reason)
		if len(r.History) > 10 {
			r.History = r.History[len(r.History)-10:]
		}
	}

	// Adaptive Penalty: Increase penalty based on previous violations.
	// penalty * (1 + log2(violations))
	adaptivePenalty := penalty * (1.0 + math.Log2(float64(r.ViolationCount)))

	r.Score -= adaptivePenalty
	if r.Score < 0 {
		r.Score = 0
	}

	// Adaptive Recovery: Slower recovery if many violations.
	// rate = 1.0 / (1 + violations/5)
	r.RecoveryRate = 1.0 / (1.0 + float64(r.ViolationCount)/5.0)

	r.LastEvent = time.Now()
	reputationCache.Add(fingerprint, r)

	// Broadcast the update to the cluster via Gossip.
	BroadcastReputation(fingerprint, r.Score, r.ViolationCount, r.History)
}

// ApplyRemoteReputation updates a score from a gossip message without re-broadcasting.
func ApplyRemoteReputation(fingerprint string, score float64, violations int, history []string) {
	if fingerprint == "" {
		return
	}
	repMu.Lock()
	defer repMu.Unlock()

	var r *Reputation
	if val, ok := reputationCache.Get(fingerprint); ok {
		r = val.(*Reputation)
		// Only take the remote score if it's worse (lower) than ours.
		if score < r.Score {
			r.Score = score
			r.ViolationCount = violations
			r.History = history
			r.LastEvent = time.Now()
		}
	} else {
		r = &Reputation{
			Score:          score,
			ViolationCount: violations,
			RecoveryRate:   1.0 / (1.0 + float64(violations)/5.0),
			History:        history,
			LastEvent:      time.Now(),
		}
	}

	reputationCache.Add(fingerprint, r)
}

type ReputationRecord struct {
	Fingerprint    string
	Score          float64
	LastEvent      time.Time
	ViolationCount int
	History        []string
}

// UpdateReputationMetrics updates Prometheus gauges for reputations.
func UpdateReputationMetrics() {
	repMu.Lock()
	defer repMu.Unlock()

	keys := reputationCache.Keys()
	var suspiciousCount float64
	for _, k := range keys {
		if val, ok := reputationCache.Peek(k); ok {
			r := val.(*Reputation)
			if r.Score < 50 {
				suspiciousCount++
			}
			ActiveAnomalyScore.Observe(r.Score)
		}
	}
	ActiveSuspiciousSessionsTotal.Set(suspiciousCount)
}

// GetAllReputations returns all reputations in the cache.
func GetAllReputations() []ReputationRecord {
	UpdateReputationMetrics()

	repMu.Lock()
	defer repMu.Unlock()

	keys := reputationCache.Keys()
	res := make([]ReputationRecord, 0, len(keys))
	for _, k := range keys {
		if val, ok := reputationCache.Peek(k); ok {
			r := val.(*Reputation)
			res = append(res, ReputationRecord{
				Fingerprint:    k.(string),
				Score:          r.Score,
				LastEvent:      r.LastEvent,
				ViolationCount: r.ViolationCount,
				History:        slices.Clone(r.History),
			})
		}
	}
	return res
}
