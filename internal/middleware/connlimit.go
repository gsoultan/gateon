package middleware

import (
	"net/http"
	"sync"

	"github.com/gateon/gateon/internal/httputil"
	"github.com/gateon/gateon/internal/telemetry"
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
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				inflightRejectedTotal.WithLabelValues("max_connections").Inc()
				telemetry.IncInflightRejected("max_connections")
				w.Header().Set("Retry-After", "60")
				httputil.WriteJSONError(w, http.StatusServiceUnavailable, "too many connections", "")
			}
		})
	}
}

// MaxConnectionsPerIP limits concurrent in-flight requests per client IP.
func MaxConnectionsPerIP(max int, keyFunc func(*http.Request) string) Middleware {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	m := &perIPConnMap{buckets: make(map[string]*connBucket)}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				inflightRejectedTotal.WithLabelValues("max_connections_per_ip").Inc()
				telemetry.IncInflightRejected("max_connections_per_ip")
				w.Header().Set("Retry-After", "1")
				httputil.WriteJSONError(w, http.StatusTooManyRequests, "too many connections from this IP", "")
			}
		})
	}
}

type perIPConnMap struct {
	mu      sync.Mutex
	buckets map[string]*connBucket
}

type connBucket struct {
	sem chan struct{}
	ref int
}

func (m *perIPConnMap) get(key string, cap int) *connBucket {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.buckets[key]
	if !ok {
		b = &connBucket{sem: make(chan struct{}, cap)}
		m.buckets[key] = b
	}
	b.ref++
	return b
}

func (m *perIPConnMap) release(key string, b *connBucket) {
	<-b.sem
	m.mu.Lock()
	defer m.mu.Unlock()
	b.ref--
	if b.ref <= 0 {
		delete(m.buckets, key)
	}
}
