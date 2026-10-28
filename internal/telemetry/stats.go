// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"math"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/request"
)

// maxPathStatsMapSize limits in-memory path stats to avoid unbounded growth.
// When exceeded, the oldest ~25% of keys are evicted (by iterating and deleting).
const (
	maxPathStatsMapSize = 50000
	pathStatsShards     = 64
)

// PathStats holds aggregated statistics for a host/path combination.
type PathStats struct {
	Host              string  `json:"host"`
	Path              string  `json:"path"`
	RequestCount      uint64  `json:"requestCount"`
	BytesTotal        uint64  `json:"bytesTotal"`
	LatencySumSeconds float64 `json:"latencySumSeconds"`
	AvgLatencySeconds float64 `json:"avgLatencySeconds"`
}

// TrafficSample represents a point in time for traffic/bandwidth charts.
type TrafficSample struct {
	Timestamp int64  `json:"ts"`
	Requests  uint64 `json:"requests"`
	Bytes     uint64 `json:"bytes"`
}

// DomainStats holds aggregated statistics for a domain.
type DomainStats struct {
	Domain            string  `json:"domain"`
	Hour              int     `json:"hour,omitzero"`
	RequestCount      uint64  `json:"requestCount"`
	BytesTotal        uint64  `json:"bytesTotal"`
	LatencySumSeconds float64 `json:"latencySumSeconds"`
	AvgLatencySeconds float64 `json:"avgLatencySeconds"`
}

type pathStatsShard struct {
	mu sync.RWMutex
	m  map[pathKey]*pathStatsInternal
}

// pathKey is what a path's statistics are kept under: the host and the path
// as they are, so a lookup costs no concatenated string per request.
type pathKey struct {
	host, path string
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
			m: make(map[pathKey]*pathStatsInternal),
		}
	}
}

func getPathShard(key pathKey) *pathStatsShard {
	var h uint32 = 2166136261
	for i := range len(key.host) {
		h ^= uint32(key.host[i])
		h *= 16777619
	}
	h ^= uint32(':')
	h *= 16777619
	for i := range len(key.path) {
		h ^= uint32(key.path[i])
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

	// Both halves are bounded in length, not just in count. The map is capped
	// at maxPathStatsMapSize entries, but nothing limits how long a URI or a
	// Host may be -- there is no StatusRequestURITooLong anywhere in this tree
	// and the header budget is 1 MiB -- so a 200 KB path made each entry 400 KB
	// and the count cap alone allowed roughly 19 GiB on a 2 GB host. Count
	// eviction could not save it either: it fires per shard at 781 entries, and
	// a few thousand oversized entries spread over 64 shards never reach that.
	//
	// The retained strings are re-sliced copies, so the originals are not
	// pinned by these.
	host = truncateLabel(host)
	path = truncateLabel(path)

	key := pathKey{host: host, path: path}
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

// maxRecordedHostLen bounds the host a trace keeps. A DNS name is at most 253
// bytes, and a port and IPv6 brackets add at most nine more. The Host header is
// the client's to write, up to the server's header limit, so anything longer is
// not a host and is not stored on every trace.
const maxRecordedHostLen = 262

// requestHost returns the host at the front of a trace's requestURI, which the
// metrics middleware records as the request's host followed by its request
// target (origHost + r.URL.RequestURI()). It is "" when there is none -- a
// request with no Host, an asterisk-form target -- or when the value is too long
// to be a host. It slices requestURI rather than copying it, and looks no
// further than a host can reach, so recording it allocates nothing.
func requestHost(requestURI string) string {
	head := requestURI[:min(len(requestURI), maxRecordedHostLen+1)]
	i := strings.IndexByte(head, '/')
	if i <= 0 {
		return ""
	}
	return requestURI[:i]
}

// Authorization schemes whose credentials carry a password: Basic sends one,
// and a Digest response is derived from one.
const (
	authSchemeBasic  = "Basic"
	authSchemeDigest = "Digest"
)

// presentsPassword reports whether a request's Authorization header carries a
// password, which is what makes a refused GET a guess rather than a poll.
//
// Bearer and every other scheme carry a token the server issued; a client that
// keeps presenting a stale one is a session that ended, not someone guessing,
// and the brute-force check must not report it any more than it reports a tab
// whose session cookie expired. NTLM and Negotiate are left out as well: their
// handshake answers its first legs 401 by design.
//
// It reads the scheme and nothing after it, and allocates nothing.
func presentsPassword(header map[string][]string) bool {
	for _, v := range header["Authorization"] {
		if hasAuthScheme(v, authSchemeBasic) || hasAuthScheme(v, authSchemeDigest) {
			return true
		}
	}
	return false
}

// hasAuthScheme reports whether an Authorization value is credentials of the
// given scheme: the scheme's name, matched without regard to case as RFC 9110
// requires, then a space and something after it.
func hasAuthScheme(value, scheme string) bool {
	n := len(scheme)
	return len(value) > n+1 && value[n] == ' ' && strings.EqualFold(value[:n], scheme)
}

// firstRefusal is the trace's Refusal for a recorder's optional refusal
// argument: why the gateway itself refused the request (request.Refusal),
// which the recording site reads from the request state and nowhere else.
// Absent, or more than one given, the first counts.
func firstRefusal(refusal []request.Refusal) request.Refusal {
	if len(refusal) == 0 {
		return request.RefusalNone
	}
	return refusal[0]
}

// TraceInput is one request as a recorder hands it to the trace store,
// passed by value: it is copied into a pooled record, and a pointer would send
// it to the heap.
//
// OperationName and RequestURI are what they say when given. Left empty, they
// are derived on the store's goroutine (processTrace), so the request does not
// pay for building them: OperationName from Method and Path, and RequestURI
// from URIHost and URL, which is copied when the trace is recorded.
type TraceInput struct {
	ID, OperationName, ServiceName, RouteID string
	DurationMs                              float64
	Timestamp                               time.Time
	Status, Path, SourceIP, Fingerprint     string
	CountryCode, UserAgent, Method, Referer string
	RequestURI                              string
	URIHost                                 string
	URL                                     *url.URL
	JA4, JA4H                               string
	RequestHeader, ResponseHeader           map[string][]string
	RequestBody, ResponseBody               string
	Recommendation                          string
	Reputation                              float64
	EntrypointDelay, RouteDelay             float64
	MiddlewareDelay, ServiceDelay           float64
	Refusal                                 request.Refusal
}

// RecordRequestTrace records t. Its headers are snapshotted and its URL
// copied before it returns, so the caller may let the request go.
func RecordRequestTrace(t TraceInput) {
	tr := GetTraceRecord()
	tr.ID = t.ID
	tr.OperationName = t.OperationName
	tr.deriveOperation = t.OperationName == ""
	tr.ServiceName = t.ServiceName
	tr.RouteID = t.RouteID
	tr.DurationMs = t.DurationMs
	tr.Timestamp = t.Timestamp
	tr.Status = t.Status
	tr.Path = t.Path
	tr.SourceIP = t.SourceIP
	tr.Fingerprint = t.Fingerprint
	tr.CountryCode = t.CountryCode
	tr.UserAgent = t.UserAgent
	tr.Method = t.Method
	tr.Referer = t.Referer
	tr.RequestURI = t.RequestURI
	if t.RequestURI == "" && t.URL != nil {
		tr.uriHost, tr.url, tr.deriveURI = t.URIHost, *t.URL, true
	} else {
		tr.Host = requestHost(t.RequestURI)
	}
	tr.JA4 = t.JA4
	tr.JA4H = t.JA4H
	tr.PasswordAuth = presentsPassword(t.RequestHeader)
	tr.Refusal = t.Refusal.String()
	tr.rawReqHeader, tr.rawRespHeader = snapshotHeaders(t.RequestHeader, t.ResponseHeader)
	tr.RequestBody = t.RequestBody
	tr.ResponseBody = t.ResponseBody
	tr.Recommendation = t.Recommendation
	if tr.Recommendation == "" {
		tr.Recommendation = GetRecommendation(t.ID)
	}
	tr.Reputation = t.Reputation
	tr.EntrypointDelay = t.EntrypointDelay
	tr.RouteDelay = t.RouteDelay
	tr.MiddlewareDelay = t.MiddlewareDelay
	tr.ServiceDelay = t.ServiceDelay
	recordTraceToStore(tr)
}

// RecordTrace records a trace for an operation. refusal, optional, is why
// the gateway itself refused the request (see firstRefusal).
func RecordTrace(id, operationName, serviceName, routeID string, durationMs float64, timestamp time.Time, status, path, sourceIP, fingerprint, countryCode, userAgent, method, referer, requestURI, ja4, ja4h string, reqHeader, respHeader map[string][]string, recommendation string, reputation float64, entrypointDelay, routeDelay, middlewareDelay, serviceDelay float64, refusal ...request.Refusal) {
	RecordTraceDetailed(id, operationName, serviceName, routeID, durationMs, timestamp, status, path, sourceIP,
		fingerprint, countryCode, userAgent, method, referer, requestURI, ja4, ja4h, reqHeader, "", respHeader, "",
		recommendation, reputation, entrypointDelay, routeDelay, middlewareDelay, serviceDelay, refusal...)
}

// RecordTraceDetailed is RecordTrace with the request's and response's
// bodies.
func RecordTraceDetailed(id, operationName, serviceName, routeID string, durationMs float64, timestamp time.Time, status, path, sourceIP, fingerprint, countryCode, userAgent, method, referer, requestURI, ja4, ja4h string, reqHeader map[string][]string, reqBody string, respHeader map[string][]string, respBody, recommendation string, reputation float64, entrypointDelay, routeDelay, middlewareDelay, serviceDelay float64, refusal ...request.Refusal) {
	RecordRequestTrace(TraceInput{
		ID: id, OperationName: operationName, ServiceName: serviceName, RouteID: routeID,
		DurationMs: durationMs, Timestamp: timestamp, Status: status, Path: path, SourceIP: sourceIP,
		Fingerprint: fingerprint, CountryCode: countryCode, UserAgent: userAgent, Method: method,
		Referer: referer, RequestURI: requestURI, JA4: ja4, JA4H: ja4h,
		RequestHeader: reqHeader, ResponseHeader: respHeader, RequestBody: reqBody, ResponseBody: respBody,
		Recommendation: recommendation, Reputation: reputation, EntrypointDelay: entrypointDelay,
		RouteDelay: routeDelay, MiddlewareDelay: middlewareDelay, ServiceDelay: serviceDelay,
		Refusal: firstRefusal(refusal),
	})
}

// ResetPathStats clears all in-memory path statistics. Primarily for testing.
func ResetPathStats() {
	for i := range pathStatsShards {
		shard := pathShards[i]
		shard.mu.Lock()
		shard.m = make(map[pathKey]*pathStatsInternal)
		shard.mu.Unlock()
	}
}

// TrimShards evicts entries from all shards to reduce memory usage.
func TrimShards() {
	for i := range pathStatsShards {
		shard := pathShards[i]
		shard.mu.Lock()
		evictPathStatsLocked(shard)
		shard.mu.Unlock()
	}
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
				Host:              s.host,
				Path:              s.path,
				RequestCount:      count,
				BytesTotal:        bytes,
				LatencySumSeconds: SafeFloat(sumS),
				AvgLatencySeconds: SafeFloat(math.Round(avg*1000) / 1000), // Round to 3 decimal places
			})
		}
		shard.mu.RUnlock()
	}
	return result
}

// GetPathStats returns a list of aggregated path statistics.
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

// SafeFloat ensures a float64 value is finite and not NaN for JSON serialization.
func SafeFloat(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
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
