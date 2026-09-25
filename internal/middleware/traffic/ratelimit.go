// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
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

	sbPool = sync.Pool{
		New: func() any {
			return &strings.Builder{}
		},
	}
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
	lastAccess atomic.Int64  // unix seconds
	lastRate   atomic.Uint64 // bit-cast of rate.Limit (float64)
	lastBurst  atomic.Int32
}

const rateLimiterEvictInterval = 60 * time.Second
const rateLimiterEntryTTL = 5 * time.Minute
const rateLimiterShards = 16

// rateLimiterMaxEntriesPerShard bounds the keys one shard tracks.
const rateLimiterMaxEntriesPerShard = 4096

type rateLimiterShard struct {
	limiters  map[string]*rateLimiterEntry
	mu        sync.RWMutex
	nextSweep int64 // unix seconds; guarded by mu
}

// LocalRateLimiter implements a flexible local rate limiter with automatic TTL eviction.
// It uses sharding to reduce lock contention under heavy traffic.
type LocalRateLimiter struct {
	shards []*rateLimiterShard
	rate   rate.Limit
	burst  int
	ebpf   ebpf.Manager
}

// NewRateLimiter creates a new LocalRateLimiter with rate (requests per second) and burst.
// Stale entries are evicted automatically after rateLimiterEntryTTL of inactivity.
func NewRateLimiter(r rate.Limit, b int) *LocalRateLimiter {
	return NewRateLimiterWithEbpf(r, b, nil)
}

func NewRateLimiterWithEbpf(r rate.Limit, b int, e ebpf.Manager) *LocalRateLimiter {
	rl := &LocalRateLimiter{
		shards: make([]*rateLimiterShard, rateLimiterShards),
		rate:   r,
		burst:  b,
		ebpf:   e,
	}
	for i := range rateLimiterShards {
		rl.shards[i] = &rateLimiterShard{
			limiters: make(map[string]*rateLimiterEntry),
		}
	}
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

// sweepLocked drops entries this shard no longer needs. The caller holds mu.
//
// Eviction runs here rather than on a ticker goroutine because a limiter is
// built per route on every chain rebuild and nothing ever closes the old one:
// each rebuild used to leave a goroutine, and the map it swept, alive for the
// life of the process.
func (s *rateLimiterShard) sweepLocked(now int64) {
	s.nextSweep = now + int64(rateLimiterEvictInterval.Seconds())
	ttl := int64(rateLimiterEntryTTL.Seconds())
	for k, e := range s.limiters {
		if now-e.lastAccess.Load() > ttl {
			delete(s.limiters, k)
		}
	}
	if len(s.limiters) < rateLimiterMaxEntriesPerShard {
		return
	}
	// Every entry is young, which is what a flood of distinct keys looks like.
	// Keys come from the client IP, JA4H or fingerprint, so the set is chosen
	// by the caller and TTL alone is not a bound. Go randomises map iteration,
	// so this drops an arbitrary slice of the shard down to a low-water mark.
	target := rateLimiterMaxEntriesPerShard - rateLimiterMaxEntriesPerShard/8
	for k := range s.limiters {
		if len(s.limiters) <= target {
			break
		}
		delete(s.limiters, k)
	}
}

// Close releases the limiter. Eviction is inline (see sweepLocked), so there is
// no background goroutine to stop; the method stays for callers that own a
// limiter's lifetime and is safe to call more than once.
func (rl *LocalRateLimiter) Close() {}

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

func (rl *LocalRateLimiter) getLimiter(key string, reputation float64) *rate.Limiter {
	now := time.Now().Unix()
	s := rl.getShard(key)

	// Scale the configured rate and burst by reputation (0-100). A client with
	// no history scores 100, so it gets exactly the configured limit and a
	// penalised one gets proportionally less. This divided by 50 on the belief
	// that neutral was 50, which gave every well-behaved client twice the rate
	// and burst the operator configured.
	factor := reputation / 100.0
	adjRate := rl.rate * rate.Limit(factor)
	adjBurst := int32(float64(rl.burst) * factor)
	if adjBurst < 1 {
		adjBurst = 1
	}

	s.mu.RLock()
	entry, exists := s.limiters[key]
	s.mu.RUnlock()

	if exists {
		entry.lastAccess.Store(now)
		// Update limits only if they changed significantly, using atomics to avoid
		// calling entry.limiter.Limit() which takes a mutex lock.
		if entry.lastRate.Load() != math.Float64bits(float64(adjRate)) || entry.lastBurst.Load() != adjBurst {
			entry.limiter.SetLimit(adjRate)
			entry.limiter.SetBurst(int(adjBurst))
			entry.lastRate.Store(math.Float64bits(float64(adjRate)))
			entry.lastBurst.Store(adjBurst)
		}
		return entry.limiter
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	entry, exists = s.limiters[key]
	if !exists {
		if len(s.limiters) >= rateLimiterMaxEntriesPerShard || now >= s.nextSweep {
			s.sweepLocked(now)
		}
		entry = &rateLimiterEntry{limiter: rate.NewLimiter(adjRate, int(adjBurst))}
		entry.lastRate.Store(math.Float64bits(float64(adjRate)))
		entry.lastBurst.Store(adjBurst)
		s.limiters[key] = entry
	} else {
		if entry.lastRate.Load() != math.Float64bits(float64(adjRate)) || entry.lastBurst.Load() != adjBurst {
			entry.limiter.SetLimit(adjRate)
			entry.limiter.SetBurst(int(adjBurst))
			entry.lastRate.Store(math.Float64bits(float64(adjRate)))
			entry.lastBurst.Store(adjBurst)
		}
	}
	entry.lastAccess.Store(now)

	return entry.limiter
}

// Handler returns a middleware that limits requests based on a key (IP or Tenant).
func (rl *LocalRateLimiter) Handler(keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No CORS-preflight exemption: a rate limit a caller can step out
			// of by adding two headers is not a rate limit. Browsers cache a
			// preflight for MaxAge, so legitimate volume is negligible.
			key := keyFunc(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Adaptive Rate Limiting based on Reputation.
			//
			// Scoped to the client's network. GetFingerprintHash is GetJA4Plus,
			// so this used to tighten the limit for every client running the same
			// browser as one bad actor -- a throttle applied to bystanders, and a
			// cheaper attack than exhausting the limit honestly.
			reputation := telemetry.GetReputation(telemetry.GetReputationID(r))

			limiter := rl.getLimiter(key, reputation)
			if !limiter.Allow() {
				if rl.ebpf != nil {
					// Offload this IP to eBPF for 1 minute of hard rate limiting at the kernel level.
					// We calculate the minimum interval based on the current limit.
					interval := time.Second / 10 // Default fallback: 10 pps
					if rl.rate > 0 {
						interval = time.Duration(float64(time.Second) / float64(rl.rate))
					}
					// The kernel limits by address; key is a tenant or a
					// fingerprint under those strategies, never an address.
					_ = rl.ebpf.SetAdaptiveRateLimit(request.GetClientIP(r, config.EffectiveTrustCloudflare()), interval)
				}
				if !kind.ShouldSkipMetrics(r) {
					routeID := kind.GetRouteName(r)
					rateLimitRejectedTotal.WithLabelValues("local").Inc()

					telemetry.RequestFailuresTotal.WithLabelValues(routeID, "ratelimit:local").Inc()
					telemetry.IncRateLimitRejected("local")

					// Record as security threat
					telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
						SourceIP:    key,
						Type:        "rate_limit",
						Category:    "abuse",
						Severity:    kind.SeverityMedium,
						Score:       10, // Default score for rate limit violation
						Details:     fmt.Sprintf("Rate limit exceeded for key: %s", key),
						ActionTaken: kind.ActionBlocked,
						Time:        time.Now(),
						RouteID:     routeID,
						RequestURI:  r.RequestURI,
						Mitigated:   true,
					}))
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
			// No CORS-preflight exemption; see LocalRateLimiter.Handler.
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

			// Use pooled builder to avoid fmt.Sprintf allocations for keys and members
			sb := sbPool.Get().(*strings.Builder)
			sb.Reset()
			defer sbPool.Put(sb)

			sb.WriteString("ratelimit:v2:")
			sb.WriteString(key)
			redisKey := sb.String()

			minMsStr := strconv.FormatInt(minMs, 10)

			sb.Reset()
			sb.WriteString(strconv.FormatInt(nowMs, 10))
			sb.WriteByte('-')
			sb.WriteString(strconv.FormatInt(now.UnixNano(), 10))
			member := sb.String()

			// Pipeline to ensure atomicity
			pipe := rl.client.Pipeline()
			// Remove entries older than 1 minute
			pipe.ZRemRangeByScore(r.Context(), redisKey, "0", minMsStr)
			// Add current request
			pipe.ZAdd(r.Context(), redisKey, redigo.Z{Score: float64(nowMs), Member: member})
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

			// Adaptive logic for Redis.
			//
			// Scoped to the client's network. GetFingerprintHash is GetJA4Plus,
			// so this used to tighten the limit for every client running the same
			// browser as one bad actor -- a throttle applied to bystanders, and a
			// cheaper attack than exhausting the limit honestly.
			reputation := telemetry.GetReputation(telemetry.GetReputationID(r))
			adjLimit := int(float64(rl.rate+rl.burst) * (reputation * 0.01))
			if adjLimit < 1 {
				adjLimit = 1
			}

			if int(count.Val()) > adjLimit {
				if !kind.ShouldSkipMetrics(r) {
					routeID := kind.GetRouteName(r)
					rateLimitRejectedTotal.WithLabelValues("redis").Inc()

					telemetry.RequestFailuresTotal.WithLabelValues(routeID, "ratelimit:redis").Inc()
					telemetry.IncRateLimitRejected("redis")

					// Record as security threat
					telemetry.RecordSecurityThreat(telemetry.RecordSecurityThreatWithJA4(r, telemetry.SecurityThreat{
						SourceIP:    key,
						Type:        "rate_limit",
						Category:    "abuse",
						Severity:    kind.SeverityMedium,
						Score:       10,
						Details:     fmt.Sprintf("Rate limit exceeded for key: %s (distributed)", key),
						ActionTaken: kind.ActionBlocked,
						Time:        time.Now(),
						RouteID:     routeID,
						RequestURI:  r.RequestURI,
						Mitigated:   true,
					}))
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
	return request.GetClientIP(r, config.EffectiveTrustCloudflare())
}

// PerIPWithTrust returns a keyFunc that uses the given trustCloudflare setting.
func PerIPWithTrust(trustCloudflare bool) func(*http.Request) string {
	return func(r *http.Request) string {
		return request.GetClientIP(r, trustCloudflare)
	}
}

// PerTenant returns the tenant ID from context, or the client's address when
// the request carries none. It used to return "" then, and an empty key skips
// limiting: every unauthenticated request -- and every request when the limit
// sits before the auth middleware -- was never limited at all.
func PerTenant(r *http.Request) string {
	if tid, ok := r.Context().Value(auth.TenantIDContextKey).(string); ok && tid != "" {
		return tid
	}
	return "ip:" + request.GetClientIP(r, config.EffectiveTrustCloudflare())
}

// PerJA4H keys on the request's JA4H fingerprint within the client's network.
//
// JA4H identifies a browser build, not a client. Keyed on it alone, every
// client running the same browser shared one bucket, so one of them could use
// up the limit for all the rest -- a denial of service cheaper than being
// limited. The network scope is the one reputation uses (ADR 0011), and a
// request with no fingerprint falls back to its address instead of to the
// empty key, which skips limiting.
func PerJA4H(r *http.Request) string {
	return fingerprintInNetwork(telemetry.GetCachedJA4H(r), r)
}

// PerFingerprint keys on the detailed client fingerprint within the client's
// network, for the reason PerJA4H gives: the identity reputation itself is
// keyed on (ADR 0011), already composed and cached on the request.
func PerFingerprint(r *http.Request) string {
	return telemetry.GetReputationID(r)
}

func fingerprintInNetwork(fingerprint string, r *http.Request) string {
	return repid.For(fingerprint, request.GetClientIP(r, config.EffectiveTrustCloudflare()))
}
