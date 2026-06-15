package telemetry

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Cache name labels used for the telemetry cache metrics. Centralized here to
// avoid magic strings spread across the package.
const (
	cacheNameZeroTrust   = "zerotrust_user_location"
	cacheNameReputation  = "reputation"
	cacheNameBehavior    = "behavior"
	cacheNameScore       = "ip_score"
	cacheNameUnmitigated = "unmitigated_threats"
)

// Environment variables that override the default in-memory cache capacities.
// All values are entry counts and must be positive; invalid or non-positive
// values fall back to the documented default.
const (
	envZeroTrustCacheSize   = "GATEON_TELEMETRY_ZEROTRUST_CACHE_SIZE"
	envReputationCacheSize  = "GATEON_TELEMETRY_REPUTATION_CACHE_SIZE"
	envBehaviorCacheSize    = "GATEON_TELEMETRY_BEHAVIOR_CACHE_SIZE"
	envScoreCacheSize       = "GATEON_TELEMETRY_SCORE_CACHE_SIZE"
	envUnmitigatedCacheSize = "GATEON_TELEMETRY_UNMITIGATED_CACHE_SIZE"
)

// Default cache capacities (total entries across all shards where sharded).
const (
	defaultZeroTrustCacheSize   = 100_000
	defaultReputationCacheSize  = 100_000
	defaultBehaviorCacheSize    = 10_000
	defaultScoreCacheSize       = 10_000
	defaultUnmitigatedCacheSize = 1_000

	// minCacheSize guards against pathological configuration that would make
	// the cache useless (or, when sharded, round down to a zero-sized shard).
	minCacheSize = 16
	// cacheMetricsInterval controls how often cache occupancy gauges refresh.
	cacheMetricsInterval = 15 * time.Second
)

// TelemetryCacheCapacity reports the configured maximum number of entries for
// each in-memory telemetry cache.
var TelemetryCacheCapacity = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_telemetry_cache_capacity",
	Help: "Configured maximum number of entries for each in-memory telemetry cache.",
}, []string{"cache"})

// TelemetryCacheEntries reports the current number of entries held by each
// in-memory telemetry cache.
var TelemetryCacheEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Name: "gateon_telemetry_cache_entries",
	Help: "Current number of entries held by each in-memory telemetry cache.",
}, []string{"cache"})

// cacheSizeFromEnv resolves a cache capacity from an environment variable,
// falling back to def when the variable is unset, unparseable, or below the
// safe minimum. The resolved value is exported as a capacity gauge so the
// effective configuration is observable.
func cacheSizeFromEnv(envVar, cacheName string, def int) int {
	size := def
	if raw, ok := os.LookupEnv(envVar); ok {
		if parsed, err := strconv.Atoi(raw); err != nil || parsed < minCacheSize {
			logger.L.LogWarn("invalid telemetry cache size; using default",
				"env", envVar, "value", raw, "default", def)
		} else {
			size = parsed
		}
	}
	TelemetryCacheCapacity.WithLabelValues(cacheName).Set(float64(size))
	return size
}

// StartCacheMetricsLoop periodically samples the occupancy of the in-memory
// telemetry caches and publishes them as gauges. It blocks until ctx is
// cancelled and is intended to be run in its own goroutine.
func StartCacheMetricsLoop(ctx context.Context) {
	ticker := time.NewTicker(cacheMetricsInterval)
	defer ticker.Stop()

	for {
		sampleCacheOccupancy()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sampleCacheOccupancy reads the current entry count of every telemetry cache
// and updates the corresponding gauge. Sharded caches are summed.
func sampleCacheOccupancy() {
	if userLocationCache != nil {
		TelemetryCacheEntries.WithLabelValues(cacheNameZeroTrust).Set(float64(userLocationCache.Len()))
	}

	reputationEntries := 0
	for _, shard := range repShards {
		if shard == nil || shard.cache == nil {
			continue
		}
		shard.mu.RLock()
		reputationEntries += shard.cache.Len()
		shard.mu.RUnlock()
	}
	TelemetryCacheEntries.WithLabelValues(cacheNameReputation).Set(float64(reputationEntries))

	behaviorEntries := 0
	for _, shard := range shards {
		if shard == nil || shard.cache == nil {
			continue
		}
		shard.mu.Lock()
		behaviorEntries += shard.cache.Len()
		shard.mu.Unlock()
	}
	TelemetryCacheEntries.WithLabelValues(cacheNameBehavior).Set(float64(behaviorEntries))

	storeMu.Lock()
	st := store
	storeMu.Unlock()
	if st != nil {
		if st.scoreCache != nil {
			TelemetryCacheEntries.WithLabelValues(cacheNameScore).Set(float64(st.scoreCache.Len()))
		}
		if st.unmitigatedCache != nil {
			TelemetryCacheEntries.WithLabelValues(cacheNameUnmitigated).Set(float64(st.unmitigatedCache.Len()))
		}
	}
}
