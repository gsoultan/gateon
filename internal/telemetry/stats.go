package telemetry

import (
	"context"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
)

// maxPathStatsMapSize limits in-memory path stats to avoid unbounded growth.
// When exceeded, the oldest ~25% of keys are evicted (by iterating and deleting).
const (
	maxPathStatsMapSize = 50000
	pathStatsShards     = 64
)

// PathStats holds aggregated statistics for a host/path combination.
type PathStats struct {
	Host         string  `json:"host"`
	Path         string  `json:"path"`
	RequestCount uint64  `json:"request_count"`
	BytesTotal   uint64  `json:"bytes_total"`
	LatencySum   float64 `json:"latency_sum_seconds"`
	AvgLatency   float64 `json:"avg_latency_seconds"`
}

// TrafficSample represents a point in time for traffic/bandwidth charts.
type TrafficSample struct {
	Timestamp int64  `json:"ts"`
	Requests  uint64 `json:"requests"`
	Bytes     uint64 `json:"bytes"`
}

// DomainStats holds aggregated statistics for a domain.
type DomainStats struct {
	Domain       string  `json:"domain"`
	Hour         int     `json:"hour,omitzero"`
	RequestCount uint64  `json:"request_count"`
	BytesTotal   uint64  `json:"bytes_total"`
	LatencySum   float64 `json:"latency_sum_seconds"`
	AvgLatency   float64 `json:"avg_latency_seconds"`
}

type pathStatsShard struct {
	mu sync.RWMutex
	m  map[string]*pathStatsInternal
}

var (
	pathShards [pathStatsShards]*pathStatsShard

	internalPaths = map[string]bool{
		"/metrics": true,
		"/healthz": true,
		"/readyz":  true,
	}
)

func init() {
	for i := range pathStatsShards {
		pathShards[i] = &pathStatsShard{
			m: make(map[string]*pathStatsInternal),
		}
	}
}

func getPathShard(key string) *pathStatsShard {
	var h uint32 = 2166136261
	for i := range len(key) {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return pathShards[h%pathStatsShards]
}

type pathStatsInternal struct {
	host         string
	path         string
	requestCount uint64
	bytesTotal   uint64
	latencySum   uint64 // Store as nanoseconds for atomic update
}

// isInternalAPIPath returns true for gateway-internal paths that should not appear in path metrics.
func isInternalAPIPath(path string) bool {
	if internalPaths[path] {
		return true
	}
	return strings.HasPrefix(path, "/v1/")
}

// RecordPathRequest records a request for a host and path.
// Internal API paths (/v1/*, /metrics, /healthz, /readyz) are excluded from path metrics.
func RecordPathRequest(host, path string, latencySeconds float64, bytesTotal uint64) {
	if isInternalAPIPath(path) {
		return
	}
	// Normalize host by stripping port if present
	host = httputil.StripPort(host)

	key := host + ":" + path
	shard := getPathShard(key)

	shard.mu.RLock()
	s, ok := shard.m[key]
	shard.mu.RUnlock()

	if !ok {
		shard.mu.Lock()
		s, ok = shard.m[key]
		if !ok {
			if len(shard.m) >= maxPathStatsMapSize/pathStatsShards {
				evictPathStatsLocked(shard)
			}
			s = &pathStatsInternal{
				host: host,
				path: path,
			}
			shard.m[key] = s
		}
		shard.mu.Unlock()
	}

	atomic.AddUint64(&s.requestCount, 1)
	atomic.AddUint64(&s.bytesTotal, bytesTotal)
	atomic.AddUint64(&s.latencySum, uint64(latencySeconds*1e9))

	// Also persist to durable store if enabled (non-blocking)
	recordToStore(host, path, latencySeconds, bytesTotal, time.Now())
}

// RecordDomainRequest records a request for a domain for hourly stats.
func RecordDomainRequest(domain string, latencySeconds float64, bytesTotal uint64) {
	// Normalize domain by stripping port if present
	domain = httputil.StripPort(domain)
	// Persist to durable store for hourly aggregation
	recordDomainToStore(domain, latencySeconds, bytesTotal, time.Now())
}

// RecordTrace records a trace for an operation.
func RecordTrace(id, operationName, serviceName, routeID string, durationMs float64, timestamp time.Time, status, path, sourceIP, fingerprint, countryCode, userAgent, method, referer, requestURI, ja4, ja4h, reqHeaders, respHeaders, recommendation string, reputation float64, entrypointDelay, routeDelay, middlewareDelay, serviceDelay float64) {
	tr := GetTraceRecord()
	tr.ID = id
	tr.OperationName = operationName
	tr.ServiceName = serviceName
	tr.RouteID = routeID
	tr.DurationMs = durationMs
	tr.Timestamp = timestamp
	tr.Status = status
	tr.Path = path
	tr.SourceIP = sourceIP
	tr.Fingerprint = fingerprint
	tr.CountryCode = countryCode
	tr.UserAgent = userAgent
	tr.Method = method
	tr.Referer = referer
	tr.RequestURI = requestURI
	tr.JA4 = ja4
	tr.JA4H = ja4h
	tr.RequestHeaders = reqHeaders
	tr.ResponseHeaders = respHeaders
	if recommendation == "" {
		recommendation = GetRecommendation(id)
	}
	tr.Recommendation = recommendation
	tr.Reputation = reputation
	tr.EntrypointDelay = entrypointDelay
	tr.RouteDelay = routeDelay
	tr.MiddlewareDelay = middlewareDelay
	tr.ServiceDelay = serviceDelay
	recordTraceToStore(tr)
}

func RecordTraceDetailed(id, operationName, serviceName, routeID string, durationMs float64, timestamp time.Time, status, path, sourceIP, fingerprint, countryCode, userAgent, method, referer, requestURI, ja4, ja4h, reqHeaders, reqBody, respHeaders, respBody, recommendation string, reputation float64, entrypointDelay, routeDelay, middlewareDelay, serviceDelay float64) {
	tr := GetTraceRecord()
	tr.ID = id
	tr.OperationName = operationName
	tr.ServiceName = serviceName
	tr.RouteID = routeID
	tr.DurationMs = durationMs
	tr.Timestamp = timestamp
	tr.Status = status
	tr.Path = path
	tr.SourceIP = sourceIP
	tr.Fingerprint = fingerprint
	tr.CountryCode = countryCode
	tr.UserAgent = userAgent
	tr.Method = method
	tr.Referer = referer
	tr.RequestURI = requestURI
	tr.JA4 = ja4
	tr.JA4H = ja4h
	tr.RequestHeaders = reqHeaders
	tr.RequestBody = reqBody
	tr.ResponseHeaders = respHeaders
	tr.ResponseBody = respBody
	if recommendation == "" {
		recommendation = GetRecommendation(id)
	}
	tr.Recommendation = recommendation
	tr.Reputation = reputation
	tr.EntrypointDelay = entrypointDelay
	tr.RouteDelay = routeDelay
	tr.MiddlewareDelay = middlewareDelay
	tr.ServiceDelay = serviceDelay
	recordTraceToStore(tr)
}

// getInMemoryPathStats returns aggregated path statistics from the in-memory map.
func getInMemoryPathStats() []PathStats {
	var result []PathStats
	for i := range pathStatsShards {
		shard := pathShards[i]
		shard.mu.RLock()
		for _, s := range shard.m {
			count := atomic.LoadUint64(&s.requestCount)
			bytes := atomic.LoadUint64(&s.bytesTotal)
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
				BytesTotal:   bytes,
				LatencySum:   sumS,
				AvgLatency:   math.Round(avg*1000) / 1000, // Round to 3 decimal places
			})
		}
		shard.mu.RUnlock()
	}
	return result
}

// GetPathStats returns a list of aggregated path statistics.
// When the persistent store is enabled, it queries the DB first and falls back
// to in-memory stats when the DB returns no results (e.g. unflushed data,
// query errors, or remote DB connectivity issues).
func GetPathStats(ctx context.Context) []PathStats {
	if IsStoreEnabled() {
		days := CurrentRetentionDays()
		if days <= 0 {
			days = 1
		}
		if dbStats := GetPathStatsWindow(ctx, days); len(dbStats) > 0 {
			return dbStats
		}
	}
	return getInMemoryPathStats()
}

// evictPathStatsLocked removes about 25% of keys from the shard map.
// Must be called with shard.mu held for writing.
func evictPathStatsLocked(shard *pathStatsShard) {
	n := len(shard.m)
	if n == 0 {
		return
	}
	toEvict := (n / 4) + 1
	if toEvict > n {
		toEvict = n
	}
	for k := range shard.m {
		delete(shard.m, k)
		toEvict--
		if toEvict <= 0 {
			break
		}
	}
}
