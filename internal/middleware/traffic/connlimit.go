// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"net/http"
	"sync"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/middleware/kind"
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
func MaxConnections(max int) kind.Middleware {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	sem := make(chan struct{}, max)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No CORS-preflight exemption: a limit a caller can step out of by
			// naming a shape is not a limit. Browsers cache a preflight for
			// its max age -- the default CORS policy sends 86400 -- so
			// legitimate preflight volume is a rounding error against any cap
			// worth setting.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				if !kind.ShouldSkipMetrics(r) {
					inflightRejectedTotal.WithLabelValues("max_connections").Inc()
					telemetry.IncInflightRejected("max_connections")
				}
				w.Header().Set("Retry-After", "60")
				httputil.WriteJSONError(w, http.StatusServiceUnavailable, "too many connections", "")
			}
		})
	}
}

// ManagementInflight is MaxConnections for the management plane, which also
// answers the gateway's own liveness and readiness probes: a probe is served
// without taking a slot. Two addresses at the per-address cap could hold every
// one of the management chain's slots with slow request bodies, and /healthz
// -- from loopback too -- then answered 503, so an orchestrator's liveness
// probe restarted a gateway that was only busy (review finding MGMT-N4).
//
// The limit bounds work held in flight, and a probe holds none: it has no
// body (one that declares any is not a probe), needs no credential, and is
// answered from memory at once. It is not a shape that lets a caller step out
// of the limit with anything the limit protects; connections stay bounded by
// the listener's per-address cap. Never used on a data-plane route, where
// /healthz is the backend's path, not the gateway's.
func ManagementInflight(max int) kind.Middleware {
	limited := MaxConnections(max)
	return func(next http.Handler) http.Handler {
		l := limited(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isGatewayProbe(r) {
				next.ServeHTTP(w, r)
				return
			}
			l.ServeHTTP(w, r)
		})
	}
}

// isGatewayProbe reports whether r is a bodiless GET or HEAD of /healthz or
// /readyz.
func isGatewayProbe(r *http.Request) bool {
	if r.ContentLength != 0 || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	return r.URL.Path == "/healthz" || r.URL.Path == "/readyz"
}

// connBucket is one address's in-flight count. Every field is guarded by its
// shard's mutex: the count was a buffered channel, taken and released outside
// the lock, which cost a channel per bucket -- and a bucket per request, since
// an address's bucket is dropped when its last request ends -- on top of the
// lock the reference count needed anyway.
type connBucket struct {
	inflight int
	ref      int
}

const connLimitShards = 16

type perIPConnMap struct {
	shards []*connLimitShard
	// free holds buckets no address uses. A bucket is created when an
	// address's first request arrives and dropped when its last one ends, so
	// one request alone allocated and discarded one; pooled, a steady flow of
	// single requests reuses a handful.
	free sync.Pool
}

type connLimitShard struct {
	mu      sync.Mutex
	buckets map[string]*connBucket
}

func newPerIPConnMap() *perIPConnMap {
	m := &perIPConnMap{
		shards: make([]*connLimitShard, connLimitShards),
		free:   sync.Pool{New: func() any { return new(connBucket) }},
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

// acquire takes a slot for key when fewer than cap are in flight, and reports
// whether it did. A bucket refused a slot is dropped again at once when
// nothing else holds it, so an address that is only ever refused -- an attacker
// with a spoofable per-IP key -- never grows the map.
func (m *perIPConnMap) acquire(key string, cap int) bool {
	s := m.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		b = m.free.Get().(*connBucket)
		s.buckets[key] = b
	}
	if b.inflight >= cap {
		if b.ref == 0 {
			delete(s.buckets, key)
			m.free.Put(b)
		}
		return false
	}
	b.inflight++
	b.ref++
	return true
}

// release gives back a slot acquire granted, dropping the bucket when it was
// the last.
func (m *perIPConnMap) release(key string) {
	s := m.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		return
	}
	b.inflight--
	b.ref--
	if b.ref <= 0 {
		delete(s.buckets, key)
		b.inflight, b.ref = 0, 0
		m.free.Put(b)
	}
}

// MaxConnectionsPerIP limits concurrent in-flight requests per client IP.
func MaxConnectionsPerIP(max int, keyFunc func(*http.Request) string) kind.Middleware {
	if max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	m := newPerIPConnMap()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No CORS-preflight exemption; see MaxConnections above.
			key := keyFunc(r)
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !m.acquire(key, max) {
				if !kind.ShouldSkipMetrics(r) {
					inflightRejectedTotal.WithLabelValues("max_connections_per_ip").Inc()
					telemetry.IncInflightRejected("max_connections_per_ip")
				}
				w.Header().Set("Retry-After", "1")
				httputil.WriteJSONError(w, http.StatusTooManyRequests, "too many connections from this IP", "")
				return
			}
			defer m.release(key)
			next.ServeHTTP(w, r)
		})
	}
}
