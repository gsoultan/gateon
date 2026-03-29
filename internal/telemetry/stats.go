package telemetry

import (
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxPathStatsMapSize limits in-memory path stats to avoid unbounded growth.
// When exceeded, the oldest ~25% of keys are evicted (by iterating and deleting).
const maxPathStatsMapSize = 50000

// PathStats holds aggregated statistics for a host/path combination.
type PathStats struct {
	Host         string  `json:"host"`
	Path         string  `json:"path"`
	RequestCount uint64  `json:"request_count"`
	LatencySum   float64 `json:"latency_sum_seconds"`
	AvgLatency   float64 `json:"avg_latency_seconds"`
}

var (
	pathStatsMap = make(map[string]*pathStatsInternal)
	pathStatsMu  sync.RWMutex
)

type pathStatsInternal struct {
	host         string
	path         string
	requestCount uint64
	latencySum   uint64 // Store as nanoseconds for atomic update
}

// isInternalAPIPath returns true for gateway-internal paths that should not appear in path metrics.
func isInternalAPIPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/metrics" || path == "/healthz" || path == "/readyz"
}

// RecordPathRequest records a request for a host and path.
// Internal API paths (/v1/*, /metrics, /healthz, /readyz) are excluded from path metrics.
func RecordPathRequest(host, path string, latencySeconds float64) {
	if isInternalAPIPath(path) {
		return
	}
	// Normalize host by stripping port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	key := host + ":" + path
	pathStatsMu.RLock()
	s, ok := pathStatsMap[key]
	pathStatsMu.RUnlock()

	if !ok {
		pathStatsMu.Lock()
		s, ok = pathStatsMap[key]
		if !ok {
			if len(pathStatsMap) >= maxPathStatsMapSize {
				evictPathStatsLocked()
			}
			s = &pathStatsInternal{
				host: host,
				path: path,
			}
			pathStatsMap[key] = s
		}
		pathStatsMu.Unlock()
	}

	atomic.AddUint64(&s.requestCount, 1)
	atomic.AddUint64(&s.latencySum, uint64(latencySeconds*1e9))

	// Also persist to durable store if enabled (non-blocking)
	recordToStore(host, path, latencySeconds, time.Now())
}

// RecordTrace records a trace for an operation.
func RecordTrace(id, operationName, serviceName string, durationMs int64, timestamp time.Time, status, path string) {
	recordTraceToStore(id, operationName, serviceName, durationMs, timestamp, status, path)
}

// GetPathStats returns a list of aggregated path statistics.
func GetPathStats() []PathStats {
	// If persistent store is enabled, prefer querying it using current retention window
	if IsStoreEnabled() {
		days := CurrentRetentionDays()
		if days <= 0 {
			days = 1
		}
		return GetPathStatsWindow(days)
	}

	pathStatsMu.RLock()
	defer pathStatsMu.RUnlock()

	result := make([]PathStats, 0, len(pathStatsMap))
	for _, s := range pathStatsMap {
		count := atomic.LoadUint64(&s.requestCount)
		sumNS := atomic.LoadUint64(&s.latencySum)
		sumS := float64(sumNS) / 1e9

		avg := 0.0
		if count > 0 {
			avg = sumS / float64(count)
		}

		result = append(result, PathStats{
			Host:         s.host,
			Path:         s.path,
			RequestCount: count,
			LatencySum:   sumS,
			AvgLatency:   math.Round(avg*1000) / 1000, // Round to 3 decimal places
		})
	}
	return result
}

// evictPathStatsLocked removes about 25% of keys from pathStatsMap.
// Must be called with pathStatsMu held for writing.
func evictPathStatsLocked() {
	n := len(pathStatsMap)
	if n == 0 {
		return
	}
	toEvict := (n / 4) + 1
	if toEvict > n {
		toEvict = n
	}
	for k := range pathStatsMap {
		delete(pathStatsMap, k)
		toEvict--
		if toEvict <= 0 {
			break
		}
	}
}
