package telemetry

import (
	"cmp"
	"math"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru"
)

// GetIPFingerprint returns a unique identifier for the client (source IP).
func GetIPFingerprint(r *http.Request) string {
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

const (
	reputationShards = 16
)

type reputationShard struct {
	cache *lru.ARCCache
	mu    sync.RWMutex
	dirty map[string]struct{}
}

var (
	repShards         []*reputationShard
	lastMetricsUpdate atomic.Int64 // Unix timestamp in seconds
)

func init() {
	size := cacheSizeFromEnv(envReputationCacheSize, cacheNameReputation, defaultReputationCacheSize)
	perShard := max(size/reputationShards, 1)
	repShards = make([]*reputationShard, reputationShards)
	for i := range reputationShards {
		cache, _ := lru.NewARC(perShard)
		repShards[i] = &reputationShard{
			cache: cache,
			dirty: make(map[string]struct{}),
		}
	}
}

func getRepShard(fingerprint string) *reputationShard {
	var hash uint32 = 2166136261
	for i := range len(fingerprint) {
		hash ^= uint32(fingerprint[i])
		hash *= 16777619
	}
	return repShards[hash%reputationShards]
}

// GetReputation returns the current reputation score for a fingerprint.
// Score starts at 100 (perfect). Decreases as threats are recorded.
func GetReputation(fingerprint string) float64 {
	if fingerprint == "" {
		return 50 // Unknown
	}
	shard := getRepShard(fingerprint)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if val, ok := shard.cache.Get(fingerprint); ok {
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
			// Reset violation count if no events for a long time
			if elapsed > 24 {
				r.ViolationCount = 0
			}
			r.LastEvent = time.Now()
		}
		return r.Score
	}
	return 100
}

// GetReputationScore returns the current score for a fingerprint.
func GetReputationScore(fingerprint string) float64 {
	if fingerprint == "" {
		return 100.0
	}
	shard := getRepShard(fingerprint)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	if val, ok := shard.cache.Get(fingerprint); ok {
		return val.(*Reputation).Score
	}
	return 100.0
}

func DecreaseReputation(fingerprint string, penalty float64, reason string) {
	if fingerprint == "" {
		return
	}
	shard := getRepShard(fingerprint)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	var r *Reputation
	if val, ok := shard.cache.Get(fingerprint); ok {
		r = val.(*Reputation)
	} else {
		r = &Reputation{Score: 100, ViolationCount: 0, RecoveryRate: 1.0, History: []string{}, LastEvent: time.Now()}
	}

	r.ViolationCount++
	// 10MB limit for reputation history to avoid unbounded memory growth.
	if reason != "" {
		r.History = append(r.History, reason)
		if len(r.History) > 5 {
			r.History = r.History[len(r.History)-5:]
		}
	}
	r.LastEvent = time.Now()

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
	shard.cache.Add(fingerprint, r)

	if r.Score < 100 {
		shard.dirty[fingerprint] = struct{}{}
	} else {
		delete(shard.dirty, fingerprint)
	}

	// Automated eBPF Shunning: If reputation is very low, push to XDP layer.
	if r.Score < 20.0 {
		if m := globalEbpfManager.Load(); m != nil {
			_ = (*m).ShunIP(fingerprint)
		}
	}

	// Broadcast the update to the cluster via Gossip.
	BroadcastReputation(fingerprint, r.Score, r.ViolationCount, r.History)
}

// ApplyRemoteReputation updates a score from a gossip message without re-broadcasting.
func ApplyRemoteReputation(fingerprint string, score float64, violations int, history []string) {
	if fingerprint == "" {
		return
	}
	shard := getRepShard(fingerprint)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	var r *Reputation
	if val, ok := shard.cache.Get(fingerprint); ok {
		r = val.(*Reputation)
		// Only take the remote score if it's worse (lower) than ours,
		// OR if it's a perfect score (manual reset).
		if score < r.Score || score >= 100.0 {
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

	shard.cache.Add(fingerprint, r)
	if r.Score < 100 {
		shard.dirty[fingerprint] = struct{}{}
	} else {
		delete(shard.dirty, fingerprint)
	}
}

func ResetReputation(fingerprint string) {
	if fingerprint == "" {
		return
	}
	shard := getRepShard(fingerprint)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	shard.cache.Remove(fingerprint)
	delete(shard.dirty, fingerprint)
	// Automated eBPF Unshun: Restore access at XDP layer.
	if m := globalEbpfManager.Load(); m != nil {
		_ = (*m).UnshunIP(fingerprint)
	}
	// Broadcast a reset (score 100) to the cluster to ensure reputation is back green everywhere.
	BroadcastReputation(fingerprint, 100, 0, []string{"Manual reset"})
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
	// Rate limit metrics updates to once every 10 seconds to save CPU.
	now := time.Now().Unix()
	last := lastMetricsUpdate.Load()
	if now-last < 10 {
		return
	}
	if !lastMetricsUpdate.CompareAndSwap(last, now) {
		return
	}

	var totalScore float64
	totalCount := 0
	for _, shard := range repShards {
		shard.mu.Lock()
		shardCount := shard.cache.Len()
		totalCount += shardCount
		dirtySum := 0.0
		dirtyCount := 0
		for k := range shard.dirty {
			if val, ok := shard.cache.Get(k); ok {
				r := val.(*Reputation)
				// Check for recovery
				rate := r.RecoveryRate
				if rate <= 0 {
					rate = 1.0
				}
				elapsed := time.Since(r.LastEvent).Hours()
				if elapsed > 1 {
					r.Score = math.Min(100, r.Score+(elapsed*rate))
					if elapsed > 24 {
						r.ViolationCount = 0
					}
					r.LastEvent = time.Now()
				}

				if r.Score >= 100 {
					delete(shard.dirty, k)
				} else {
					dirtySum += r.Score
					dirtyCount++
				}
			} else {
				delete(shard.dirty, k)
			}
		}
		shard.mu.Unlock()

		// Perfect ones contribute 100 each
		totalScore += dirtySum + float64(shardCount-dirtyCount)*100
	}

	if totalCount > 0 {
		ActiveAnomalyScoreAverage.Set(totalScore / float64(totalCount))
		ActiveSuspiciousSessionsTotal.Set(float64(totalCount))
	} else {
		ActiveSuspiciousSessionsTotal.Set(0)
	}
}

// GetWorstReputations returns the top N reputations with the lowest scores.
// It is optimized to primarily scan the "dirty" set of low-reputation IPs,
// making it extremely fast even with millions of total reputation entries.
func GetWorstReputations(limit int) []ReputationRecord {
	UpdateReputationMetrics()

	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	var dirtyRecords []ReputationRecord
	for _, shard := range repShards {
		shard.mu.RLock()
		for k := range shard.dirty {
			if val, ok := shard.cache.Peek(k); ok {
				r := val.(*Reputation)
				dirtyRecords = append(dirtyRecords, ReputationRecord{
					Fingerprint:    k,
					Score:          r.Score,
					LastEvent:      r.LastEvent,
					ViolationCount: r.ViolationCount,
					History:        slices.Clone(r.History),
				})
			}
		}
		shard.mu.RUnlock()
	}

	// Sort by score ascending (worst first)
	slices.SortFunc(dirtyRecords, func(a, b ReputationRecord) int {
		return cmp.Compare(a.Score, b.Score)
	})

	if len(dirtyRecords) >= limit {
		return dirtyRecords[:limit]
	}

	// If we have fewer dirty records than the limit, fill with perfect reputations
	// from the cache until we reach the limit.
	res := dirtyRecords
	for _, shard := range repShards {
		if len(res) >= limit {
			break
		}
		shard.mu.RLock()
		keys := shard.cache.Keys()
		for _, k := range keys {
			if len(res) >= limit {
				break
			}
			fingerprint := k.(string)
			if _, isDirty := shard.dirty[fingerprint]; isDirty {
				continue
			}
			if val, ok := shard.cache.Peek(k); ok {
				r := val.(*Reputation)
				res = append(res, ReputationRecord{
					Fingerprint:    fingerprint,
					Score:          r.Score,
					LastEvent:      r.LastEvent,
					ViolationCount: r.ViolationCount,
					History:        slices.Clone(r.History),
				})
			}
		}
		shard.mu.RUnlock()
	}

	return res
}
