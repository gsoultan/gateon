// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// headerAuthorization is spelled out here rather than imported: the CORS
// factory that also names it lives in package middleware, which imports this
// package for its constructors, so reaching back for the constant would be a
// cycle. One header name is a cheaper duplicate than a shared package for it.
const headerAuthorization = "Authorization"

// CacheConfig configures the response cache.
type CacheConfig struct {
	TTLSeconds  int          // Cache TTL in seconds
	MaxEntries  int          // Max cached responses (0 = 1024, memory only)
	MaxBodyKB   int64        // Max response body to cache in KB (0 = 256)
	Storage     string       // "memory" or "redis"
	RedisClient redis.Client // Required when Storage == "redis"
}

const (
	CacheStorageMemory = "memory"
	CacheStorageRedis  = "redis"
)

// Cache returns a middleware that caches GET/HEAD responses (memory or Redis).
// The routeID parameter is used for Prometheus cache hit/miss metrics.
func Cache(cfg CacheConfig) kind.Middleware {
	return CacheWithRoute(cfg, "")
}

// CacheWithRoute returns a cache middleware that records metrics with the given route ID.
func CacheWithRoute(cfg CacheConfig, routeID string) kind.Middleware {
	if cfg.MaxBodyKB <= 0 {
		cfg.MaxBodyKB = 256
	}
	maxBody := cfg.MaxBodyKB * 1024
	ttl := time.Duration(cfg.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	var backend CacheBackend
	if cfg.Storage == CacheStorageRedis && cfg.RedisClient != nil {
		backend = NewRedisCacheBackend(cfg.RedisClient)
	}
	if backend == nil {
		if cfg.MaxEntries <= 0 {
			cfg.MaxEntries = 1024
		}
		backend = newMemoryCacheBackend(cfg.MaxEntries, maxBody)
	}

	rt := cacheRuntime{backend: backend, routeID: routeID, maxBody: maxBody, ttl: ttl}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rt.serve(next, w, r)
		})
	}
}

// cacheRuntime is CacheConfig once defaults are applied and a backend chosen.
// Resolved per route at chain-build time, never per request.
type cacheRuntime struct {
	backend CacheBackend
	routeID string
	maxBody int64
	ttl     time.Duration
}

// serve is the per-request path, named rather than nested inside the two
// closures a middleware already is -- gocognit charges each branch by its
// depth, and at depth three the branches below cost triple what they read as.
func (c cacheRuntime) serve(next http.Handler, w http.ResponseWriter, r *http.Request) {
	if kind.ShouldSkipMetrics(r) {
		next.ServeHTTP(w, r)
		return
	}

	activeRouteID := kind.GetRouteName(r)
	if activeRouteID == "" {
		activeRouteID = c.routeID
	}

	if (r.Method != http.MethodGet && r.Method != http.MethodHead) || cacheBypass(r) {
		next.ServeHTTP(w, r)
		return
	}

	key := cacheKey(activeRouteID, r)
	if status, headers, body, ok := c.backend.Get(r.Context(), key); ok {
		telemetry.MiddlewareCacheHitsTotal.WithLabelValues(activeRouteID).Inc()
		replayCached(w, r, status, headers, body)
		return
	}
	telemetry.MiddlewareCacheMissesTotal.WithLabelValues(activeRouteID).Inc()

	buf := &bytes.Buffer{}
	rec := &responseRecorder{
		ResponseWriter: w,
		status:         http.StatusOK,
		header:         make(http.Header),
		body:           buf,
		maxBody:        c.maxBody,
	}
	next.ServeHTTP(rec, r)
	rec.commitHeader()

	if rec.cacheable() {
		c.backend.Set(r.Context(), key, rec.status, rec.header, bytes.Clone(buf.Bytes()), c.ttl)
	}
}

// replayCached writes a stored response back to the client. A HEAD gets the
// headers and status of the GET it shares a key with, but never the body.
func replayCached(w http.ResponseWriter, r *http.Request, status int, headers http.Header, body []byte) {
	for k, vv := range headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(status)

	if r.Method == http.MethodGet && len(body) > 0 {
		// #nosec G705 -- a previously cached origin response replayed
		// verbatim, with the origin's stored Content-Type.
		_, _ = w.Write(body)
	}
}

// cacheBypass reports whether a response to this request is too specific to the
// caller, or too partial, to be shared with anyone else.
//
// A request carrying credentials gets a response computed for that identity, so
// storing it under a key that does not mention the identity hands the next
// caller someone else's data. Range requests are excluded because the reply is
// a fragment: caching it would serve five bytes to a client that asked for the
// whole resource.
func cacheBypass(r *http.Request) bool {
	return r.Header.Get(headerAuthorization) != "" ||
		r.Header.Get("Proxy-Authorization") != "" ||
		r.Header.Get("Cookie") != "" ||
		r.Header.Get("Range") != ""
}

// cacheKey identifies a cached response by everything that selects it.
//
// The route is included because the Redis backend is shared by every route in
// every instance of the cluster, and the method because a HEAD must not answer
// a GET. Host is included because one gateway fronts many virtual hosts and the
// origin-form request line a real client sends carries only the path.
func cacheKey(routeID string, r *http.Request) string {
	uri := r.URL.RequestURI()
	var sb strings.Builder
	sb.Grow(len(routeID) + len(r.Method) + len(r.Host) + len(uri) + 3)
	sb.WriteString(routeID)
	sb.WriteByte(0)
	sb.WriteString(r.Method)
	sb.WriteByte(0)
	sb.WriteString(r.Host)
	sb.WriteByte(0)
	sb.WriteString(uri)
	return sb.String()
}

// responseAllowsCaching applies the response-side rules the origin states in
// headers. Anything that says "this reply belongs to one caller" (Set-Cookie,
// Cache-Control private/no-store/no-cache) or "the right reply depends on a
// request header" (Vary on anything this key does not carry) is not storable.
// Content-Encoding is refused for the same reason: the key does not include
// Accept-Encoding, so a stored gzip body would reach a client that cannot
// decode it.
func responseAllowsCaching(h http.Header) bool {
	if h.Get("Set-Cookie") != "" || h.Get("Content-Encoding") != "" {
		return false
	}
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "private") {
		return false
	}
	for _, v := range h.Values("Vary") {
		for field := range strings.SplitSeq(v, ",") {
			f := strings.ToLower(strings.TrimSpace(field))
			if f != "" && f != "accept-encoding" {
				return false
			}
		}
	}
	return true
}

type cacheEntry struct {
	status   int
	headers  http.Header
	body     []byte
	expireAt time.Time
}

const cacheShards = 16

// cacheOrderSlack bounds the FIFO index relative to the entry cap.
const cacheOrderSlack = 2

// memoryCacheBackend implements CacheBackend with in-memory storage and sharding.
type memoryCacheBackend struct {
	shards []*cacheShard
}

type cacheShard struct {
	store *cacheStore
	mu    sync.Mutex
}

func newMemoryCacheBackend(max int, maxBody int64) *memoryCacheBackend {
	shardMax := max / cacheShards
	if shardMax < 1 {
		shardMax = 1
	}
	m := &memoryCacheBackend{
		shards: make([]*cacheShard, cacheShards),
	}
	for i := range cacheShards {
		m.shards[i] = &cacheShard{
			store: &cacheStore{
				entries: make(map[string]*cacheEntry),
				max:     shardMax,
				maxBody: maxBody,
			},
		}
	}
	return m
}

func (m *memoryCacheBackend) getShard(key string) *cacheShard {
	var hash uint32 = 2166136261
	for i := range len(key) {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return m.shards[hash%cacheShards]
}

func (m *memoryCacheBackend) Get(ctx context.Context, key string) (int, http.Header, []byte, bool) {
	s := m.getShard(key)
	s.mu.Lock()
	ent := s.store.get(key)
	s.mu.Unlock()
	if ent == nil {
		return 0, nil, nil, false
	}
	return ent.status, ent.headers, ent.body, true
}

func (m *memoryCacheBackend) Set(ctx context.Context, key string, status int, headers http.Header, body []byte, ttl time.Duration) {
	s := m.getShard(key)
	s.mu.Lock()
	s.store.set(key, &cacheEntry{
		status:   status,
		headers:  headers,
		body:     body,
		expireAt: time.Now().Add(ttl),
	})
	s.mu.Unlock()
}

type responseRecorder struct {
	http.ResponseWriter
	status      int
	header      http.Header
	body        *bytes.Buffer
	maxBody     int64
	wrote       int64
	wroteHeader bool
	truncated   bool
}

// commitHeader copies the handler's headers to the real writer if the handler
// never wrote any bytes and never called WriteHeader.
func (r *responseRecorder) commitHeader() {
	if !r.wroteHeader {
		r.WriteHeader(r.status)
	}
}

// cacheable reports whether what was just recorded may be stored.
//
// Only 200 qualifies: 204 and 304 have no body to replay, and 206 is a
// fragment of one. A body cut off at maxBody is refused outright -- storing the
// prefix would serve a truncated response to every later caller.
func (r *responseRecorder) cacheable() bool {
	if r.status != http.StatusOK || r.truncated || r.body == nil || r.body.Len() == 0 {
		return false
	}
	return responseAllowsCaching(r.header)
}

func (r *responseRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	for k, vv := range r.header {
		for _, v := range vv {
			r.ResponseWriter.Header().Add(k, v)
		}
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(p []byte) (n int, err error) {
	// net/http sends 200 on the first Write; do the same here so the handler's
	// headers reach the real writer instead of being dropped.
	if !r.wroteHeader {
		r.WriteHeader(r.status)
	}
	n, err = r.ResponseWriter.Write(p)
	if r.body == nil {
		return n, err
	}
	if r.wrote+int64(len(p)) > r.maxBody {
		r.truncated = true
		return n, err
	}
	r.body.Write(p)
	r.wrote += int64(len(p))
	return n, err
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (r *responseRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := r.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

type cacheStore struct {
	entries map[string]*cacheEntry
	order   []string
	max     int
	maxBody int64
}

func (s *cacheStore) get(key string) *cacheEntry {
	ent, ok := s.entries[key]
	if !ok || ent == nil || time.Now().After(ent.expireAt) {
		if ok {
			delete(s.entries, key)
		}
		return nil
	}
	return ent
}

func (s *cacheStore) set(key string, ent *cacheEntry) {
	if _, exists := s.entries[key]; !exists {
		if len(s.entries) >= s.max {
			// Evict oldest entry that still exists
			for len(s.order) > 0 {
				old := s.order[0]
				s.order = s.order[1:]
				if _, ok := s.entries[old]; ok {
					delete(s.entries, old)
					break
				}
			}
		}
		if len(s.order) >= cacheOrderSlack*s.max {
			s.compactOrder()
		}
		s.order = append(s.order, key)
	}
	s.entries[key] = ent
}

// compactOrder drops the eviction index down to one slot per live entry.
//
// A key is appended whenever it is absent from the map, so a key that expires
// and is requested again is appended again while its old slot is still in the
// slice. Under a steady stream of expiring keys the index grew without bound
// even though the map itself stayed at its cap. Walking backwards keeps each
// key's most recent slot, which is the one eviction order should use.
func (s *cacheStore) compactOrder() {
	seen := make(map[string]struct{}, len(s.entries))
	kept := make([]string, 0, len(s.entries))
	for i := len(s.order) - 1; i >= 0; i-- {
		k := s.order[i]
		if _, live := s.entries[k]; !live {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		kept = append(kept, k)
	}
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	s.order = kept
}
