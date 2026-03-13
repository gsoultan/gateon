package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gateon/gateon/internal/httputil"
	"github.com/gateon/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
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

// LocalRateLimiter implements a flexible local rate limiter.
type LocalRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

// NewRateLimiter creates a new LocalRateLimiter with rate (requests per second) and burst.
func NewRateLimiter(r rate.Limit, b int) *LocalRateLimiter {
	return &LocalRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
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
	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	limiter, exists = rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[key] = limiter
	}

	return limiter
}

// Handler returns a middleware that limits requests based on a key (IP or Tenant).
func (rl *LocalRateLimiter) Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			limiter := rl.getLimiter(key)
			if !limiter.Allow() {
				rateLimitRejectedTotal.WithLabelValues("local").Inc()
				telemetry.IncRateLimitRejected("local")
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
	client *redis.Client
	rate   int // requests per minute
	burst  int
}

func NewRedisRateLimiter(client *redis.Client, r int, b int) *RedisRateLimiter {
	return &RedisRateLimiter{
		client: client,
		rate:   r,
		burst:  b,
	}
}

func (rl *RedisRateLimiter) Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			pipe.ZAdd(r.Context(), redisKey, redis.Z{Score: float64(nowMs), Member: fmt.Sprintf("%d-%d", nowMs, now.UnixNano())})
			// Count requests in the window
			pipe.ZCard(r.Context(), redisKey)
			// Set expiration to clean up unused keys
			pipe.Expire(r.Context(), redisKey, 2*time.Minute)

			cmds, err := pipe.Exec(r.Context())
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			count, ok := cmds[2].(*redis.IntCmd)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			if int(count.Val()) > rl.rate+rl.burst {
				rateLimitRejectedTotal.WithLabelValues("redis").Inc()
				telemetry.IncRateLimitRejected("redis")
				w.Header().Set("Retry-After", "1")
				httputil.WriteJSONError(w, http.StatusTooManyRequests, "too many requests (distributed)", "")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PerIP returns the client's IP address, normalized (no port) for consistent rate-limit keys.
func PerIP(r *http.Request) string {
	raw := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		raw = strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	ip, _, err := net.SplitHostPort(raw)
	if err != nil {
		return raw
	}
	return ip
}

// PerTenant returns the tenant ID from context.
func PerTenant(r *http.Request) string {
	if tid, ok := r.Context().Value(TenantIDContextKey).(string); ok {
		return tid
	}
	return ""
}
