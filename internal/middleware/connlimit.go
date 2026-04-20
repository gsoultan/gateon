package middleware

import (
	"net/http"
	"sync"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	inflightRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "gateon_inflight_rejected_total",
		Help: "Total number of requests rejected by in-flight connection limits",
	}, []string{"reason"})
)

// MaxConnections returns a middleware that limits concurrent requests.
// When the limit is reached, requests receive 503 Service Unavailable.
func MaxConnections(max int) Middleware {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	sem := make(chan struct{}, max)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsCorsPreflight(r) {
				next.ServeHTTP(w, r)
				return
			}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				if !ShouldSkipMetrics(r) {
					inflightRejectedTotal.WithLabelValues("max_connections").Inc()
					telemetry.IncInflightRejected("max_connections")
				}
				w.Header().Set("Retry-After", "60")
				httputil.WriteJSONError(w, http.StatusServiceUnavailable, "too many connections", "")
			}
		})
	}
}

type connBucket struct {
	sem chan struct{}
	ref int
}

const connLimitShards = 16

type perIPConnMap struct {
	shards []*connLimitShard
}

type connLimitShard struct {
	mu      sync.Mutex
	buckets map[string]*connBucket
}

func newPerIPConnMap() *perIPConnMap {
	m := &perIPConnMap{
		shards: make([]*connLimitShard, connLimitShards),
	}
	for i := range connLimitShards {
		m.shards[i] = &connLimitShard{
			buckets: make(map[string]*connBucket),
		}
	}
	return m
}

func (m *perIPConnMap) getShard(key string) *connLimitShard {
	var hash uint32 = 2166136261
	for i := range len(key) {
		hash ^= uint32(key[i])
		hash *= 16777619
	}
	return m.shards[hash%connLimitShards]
}

func (m *perIPConnMap) get(key string, cap int) *connBucket {
	s := m.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		b = &connBucket{sem: make(chan struct{}, cap)}
		s.buckets[key] = b
	}
	b.ref++
	return b
}

func (m *perIPConnMap) release(key string, b *connBucket) {
	<-b.sem
	s := m.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b.ref--
	if b.ref <= 0 {
		delete(s.buckets, key)
	}
}

// MaxConnectionsPerIP limits concurrent in-flight requests per client IP.
func MaxConnectionsPerIP(max int, keyFunc func(*http.Request) string) Middleware {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	m := newPerIPConnMap()
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
			b := m.get(key, max)
			select {
			case b.sem <- struct{}{}:
				defer m.release(key, b)
				next.ServeHTTP(w, r)
			default:
				if !ShouldSkipMetrics(r) {
					inflightRejectedTotal.WithLabelValues("max_connections_per_ip").Inc()
					telemetry.IncInflightRejected("max_connections_per_ip")
				}
				w.Header().Set("Retry-After", "1")
				httputil.WriteJSONError(w, http.StatusTooManyRequests, "too many connections from this IP", "")
			}
		})
	}
}
