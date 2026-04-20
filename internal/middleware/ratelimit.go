package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	redigo "github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

var (
	rateLimitRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateon_ratelimit_rejected_total",
		Help: "Total number of requests rejected by the rate limiter",
	}, []string{"backend"})
)

// RateLimiter defines the interface for rate limiting.
type RateLimiter interface {
	Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler
}

// NoopRateLimiter passes all requests through; use when GATEON_ENTRYPOINT_RATE_LIMIT_QPS=0 for high throughput.
type NoopRateLimiter struct{}

// Handler returns a middleware that passes through without rate limiting.
func (NoopRateLimiter) Handler(_ func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}

// rateLimiterEntry holds a rate limiter and its last access time for TTL eviction.
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess atomic.Int64 // unix seconds
}

const rateLimiterEvictInterval = 60 * time.Second
const rateLimiterEntryTTL = 5 * time.Minute
const rateLimiterShards = 16

type rateLimiterShard struct {
	limiters map[string]*rateLimiterEntry
	mu       sync.RWMutex
}

// LocalRateLimiter implements a flexible local rate limiter with automatic TTL eviction.
// It uses sharding to reduce lock contention under heavy traffic.
type LocalRateLimiter struct {
	shards    []*rateLimiterShard
	rate      rate.Limit
	burst     int
	stopEvict chan struct{}
}

// NewRateLimiter creates a new LocalRateLimiter with rate (requests per second) and burst.
// Stale entries are evicted automatically after rateLimiterEntryTTL of inactivity.
func NewRateLimiter(r rate.Limit, b int) *LocalRateLimiter {
	rl := &LocalRateLimiter{
		shards:    make([]*rateLimiterShard, rateLimiterShards),
		rate:      r,
		burst:     b,
		stopEvict: make(chan struct{}),
	}
	for i := range rateLimiterShards {
		rl.shards[i] = &rateLimiterShard{
			limiters: make(map[string]*rateLimiterEntry),
		}
	}
	go rl.evictLoop()
	return rl
}

func (rl *LocalRateLimiter) getShard(key string) *rateLimiterShard {
	var hash uint32 = 2166136261
	for i := range len(key) {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return rl.shards[hash%rateLimiterShards]
}

// evictLoop periodically removes stale rate limiter entries from all shards.
func (rl *LocalRateLimiter) evictLoop() {
	ticker := time.NewTicker(rateLimiterEvictInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			ttl := int64(rateLimiterEntryTTL.Seconds())
			for _, s := range rl.shards {
				s.mu.Lock()
				for k, e := range s.limiters {
					if now-e.lastAccess.Load() > ttl {
						delete(s.limiters, k)
					}
				}
				s.mu.Unlock()
			}
		case <-rl.stopEvict:
			return
		}
	}
}

// Close stops the background eviction goroutine.
func (rl *LocalRateLimiter) Close() {
	close(rl.stopEvict)
}

// NewQPSRateLimiter creates a LocalRateLimiter for the given requests per second and burst.
// Use this when you have integer QPS values (e.g. 10 req/s, 20 burst).
func NewQPSRateLimiter(requestsPerSec, burst int) *LocalRateLimiter {
	if requestsPerSec <= 0 {
		requestsPerSec = 1
	}
	if burst <= 0 {
		burst = 5
	}
	return NewRateLimiter(rate.Limit(requestsPerSec), burst)
}

func (rl *LocalRateLimiter) getLimiter(key string) *rate.Limiter {
	now := time.Now().Unix()
	s := rl.getShard(key)

	s.mu.RLock()
	entry, exists := s.limiters[key]
	s.mu.RUnlock()

	if exists {
		entry.lastAccess.Store(now)
		return entry.limiter
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	entry, exists = s.limiters[key]
	if !exists {
		entry = &rateLimiterEntry{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		s.limiters[key] = entry
	}
	entry.lastAccess.Store(now)

	return entry.limiter
}

// Handler returns a middleware that limits requests based on a key (IP or Tenant).
func (rl *LocalRateLimiter) Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			key := keyFunc(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			limiter := rl.getLimiter(key)
			if !limiter.Allow() {
				if !ShouldSkipMetrics(r) {
					routeID := GetRouteName(r)
					rateLimitRejectedTotal.WithLabelValues("local").Inc()
					telemetry.MiddlewareRateLimitRejectedTotal.WithLabelValues(routeID, "local").Inc()
					telemetry.IncRateLimitRejected("local")
				}
				w.Header().Set("Retry-After", "1")
				httputil.WriteJSONError(w, http.StatusTooManyRequests, "too many requests", "")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RedisRateLimiter implements a flexible distributed rate limiter using Redis.
type RedisRateLimiter struct {
	client redis.Client
	rate   int // requests per minute
	burst  int
}

func NewRedisRateLimiter(client redis.Client, r int, b int) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		rate:   r,
		burst:  b,
	}
}

func (rl *RedisRateLimiter) Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			key := keyFunc(r)
			if key == "" || rl.client == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Sliding window implementation using a Redis Sorted Set
			// Every request is a member with current timestamp as score
			now := time.Now()
			nowMs := now.UnixMilli()
			windowMs := int64(60 * 1000) // 1 minute window
			minMs := nowMs - windowMs
			redisKey := fmt.Sprintf("ratelimit:v2:%s", key)

			// Pipeline to ensure atomicity
			pipe := rl.client.Pipeline()
			// Remove entries older than 1 minute
			pipe.ZRemRangeByScore(r.Context(), redisKey, "0", fmt.Sprintf("%d", minMs))
			// Add current request
			pipe.ZAdd(r.Context(), redisKey, redigo.Z{Score: float64(nowMs), Member: fmt.Sprintf("%d-%d", nowMs, now.UnixNano())})
			// Count requests in the window
			pipe.ZCard(r.Context(), redisKey)
			// Set expiration to clean up unused keys
			pipe.Expire(r.Context(), redisKey, 2*time.Minute)

			cmds, err := pipe.Exec(r.Context())
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			count, ok := cmds[2].(*redigo.IntCmd)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			if int(count.Val()) > rl.rate+rl.burst {
				if !ShouldSkipMetrics(r) {
					routeID := GetRouteName(r)
					rateLimitRejectedTotal.WithLabelValues("redis").Inc()
					telemetry.MiddlewareRateLimitRejectedTotal.WithLabelValues(routeID, "redis").Inc()
					telemetry.IncRateLimitRejected("redis")
				}
				w.Header().Set("Retry-After", "1")
				httputil.WriteJSONError(w, http.StatusTooManyRequests, "too many requests (distributed)", "")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PerIP returns the client's IP address for rate-limit keys (uses X-Forwarded-For by default).
func PerIP(r *http.Request) string {
	return request.GetClientIP(r, request.TrustCloudflareFromEnv())
}

// PerIPWithTrust returns a keyFunc that uses the given trustCloudflare setting.
func PerIPWithTrust(trustCloudflare bool) func(*http.Request) string {
	return func(r *http.Request) string {
		return request.GetClientIP(r, trustCloudflare)
	}
}

// PerTenant returns the tenant ID from context.
func PerTenant(r *http.Request) string {
	if tid, ok := r.Context().Value(TenantIDContextKey).(string); ok {
		return tid
	}
	return ""
}
