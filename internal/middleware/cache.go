package middleware

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/telemetry"
)

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
func Cache(cfg CacheConfig) Middleware {
	return CacheWithRoute(cfg, "")
}

// CacheWithRoute returns a cache middleware that records metrics with the given route ID.
func CacheWithRoute(cfg CacheConfig, routeID string) Middleware {
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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ShouldSkipMetrics(r) {
				next.ServeHTTP(w, r)
				return
			}
			activeRouteID := GetRouteName(r)
			if activeRouteID == "" {
				activeRouteID = routeID
			}

			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			key := r.URL.String()
			status, headers, body, ok := backend.Get(r.Context(), key)
			if ok {
				telemetry.MiddlewareCacheHitsTotal.WithLabelValues(activeRouteID).Inc()
				for k, vv := range headers {
					for _, v := range vv {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(status)
				if r.Method == http.MethodGet && len(body) > 0 {
					_, _ = w.Write(body)
				}
				return
			}
			telemetry.MiddlewareCacheMissesTotal.WithLabelValues(activeRouteID).Inc()

			buf := &bytes.Buffer{}
			rec := &responseRecorder{
				ResponseWriter: w,
				status:         http.StatusOK,
				header:         make(http.Header),
				body:           buf,
				maxBody:        maxBody,
			}
			next.ServeHTTP(rec, r)

			if rec.status >= 200 && rec.status < 300 && buf.Len() > 0 && int64(buf.Len()) <= maxBody {
				backend.Set(r.Context(), key, rec.status, rec.header, bytes.Clone(buf.Bytes()), ttl)
			}
		})
	}
}

type cacheEntry struct {
	status   int
	headers  http.Header
	body     []byte
	expireAt time.Time
}

const cacheShards = 16

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
	status  int
	header  http.Header
	body    *bytes.Buffer
	maxBody int64
	wrote   int64
}

func (r *responseRecorder) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	for k, vv := range r.header {
		for _, v := range vv {
			r.ResponseWriter.Header().Add(k, v)
		}
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(p []byte) (n int, err error) {
	n, err = r.ResponseWriter.Write(p)
	if r.body != nil && r.wrote < r.maxBody {
		remain := r.maxBody - r.wrote
		if int64(len(p)) <= remain {
			r.body.Write(p)
			r.wrote += int64(len(p))
		} else {
			r.body.Write(p[:remain])
			r.wrote = r.maxBody
		}
	}
	return n, err
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
		s.order = append(s.order, key)
	}
	s.entries[key] = ent
}
