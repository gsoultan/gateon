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
	m.unref(key, b)
}

// unref drops the reference taken by get() WITHOUT consuming a semaphore slot.
// It must be used on the reject path, where get() incremented ref but no slot
// was ever acquired (so release()'s `<-b.sem` would block/underflow). Without
// this, every rejected request leaks a ref and the bucket is never evicted,
// allowing an attacker (especially with a spoofable per-IP key) to grow the
// bucket map without bound.
func (m *perIPConnMap) unref(key string, b *connBucket) {
	s := m.getShard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	b.ref--
	if b.ref <= 0 {
		delete(s.buckets, key)
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
			b := m.get(key, max)
			select {
			case b.sem <- struct{}{}:
				defer m.release(key, b)
				next.ServeHTTP(w, r)
			default:
				// Rejected: drop the ref taken by get() (no slot acquired).
				m.unref(key, b)
				if !kind.ShouldSkipMetrics(r) {
					inflightRejectedTotal.WithLabelValues("max_connections_per_ip").Inc()
					telemetry.IncInflightRejected("max_connections_per_ip")
				}
				w.Header().Set("Retry-After", "1")
				httputil.WriteJSONError(w, http.StatusTooManyRequests, "too many connections from this IP", "")
			}
		})
	}
}
