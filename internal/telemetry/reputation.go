package telemetry

import (
	"math"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

type Reputation struct {
	Score     float64
	LastEvent time.Time
}

var (
	reputationCache *lru.ARCCache
	repMu           sync.Mutex
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
		// Gradually recover reputation over time (1 point per hour)
		elapsed := time.Since(r.LastEvent).Hours()
		if elapsed > 1 {
			r.Score = math.Min(100, r.Score+elapsed)
		}
		return r.Score
	}
	return 100
}

// DecreaseReputation reduces the score based on threat severity.
func DecreaseReputation(fingerprint string, penalty float64) {
	if fingerprint == "" {
		return
	}
	repMu.Lock()
	defer repMu.Unlock()

	var r *Reputation
	if val, ok := reputationCache.Get(fingerprint); ok {
		r = val.(*Reputation)
	} else {
		r = &Reputation{Score: 100}
	}

	r.Score -= penalty
	if r.Score < 0 {
		r.Score = 0
	}
	r.LastEvent = time.Now()
	reputationCache.Add(fingerprint, r)
}

type ReputationRecord struct {
	Fingerprint string
	Score       float64
	LastEvent   time.Time
}

// GetAllReputations returns all reputations in the cache.
func GetAllReputations() []ReputationRecord {
	repMu.Lock()
	defer repMu.Unlock()

	keys := reputationCache.Keys()
	res := make([]ReputationRecord, 0, len(keys))
	var suspiciousCount float64
	for _, k := range keys {
		if val, ok := reputationCache.Peek(k); ok {
			r := val.(*Reputation)
			res = append(res, ReputationRecord{
				Fingerprint: k.(string),
				Score:       r.Score,
				LastEvent:   r.LastEvent,
			})
			if r.Score < 50 {
				suspiciousCount++
			}
			ActiveAnomalyScore.Observe(r.Score)
		}
	}
	ActiveSuspiciousSessionsTotal.Set(suspiciousCount)
	return res
}
