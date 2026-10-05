// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// blackholeTransport stands in for targets that never answer. A check waits
// until want checks are in flight at once -- proof they overlap -- or until
// bound passes, the way a blackholed target's check waits out its timeout;
// then it fails.
type blackholeTransport struct {
	want     int32
	bound    time.Duration
	inflight atomic.Int32
	max      atomic.Int32
	once     sync.Once
	together chan struct{}
}

func newBlackhole(want int, bound time.Duration) *blackholeTransport {
	return &blackholeTransport{want: int32(want), bound: bound, together: make(chan struct{})}
}

var errBlackholed = errors.New("blackholed")

func (b *blackholeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	n := b.inflight.Add(1)
	defer b.inflight.Add(-1)
	for m := b.max.Load(); n > m && !b.max.CompareAndSwap(m, n); m = b.max.Load() {
	}
	if n >= b.want {
		b.once.Do(func() { close(b.together) })
	}
	select {
	case <-b.together:
	case <-time.After(b.bound):
	}
	return nil, errBlackholed
}

func blackholedService(id string, k int) *gateonv1.Service {
	targets := make([]*gateonv1.Target, k)
	for i := range targets {
		targets[i] = &gateonv1.Target{Url: fmt.Sprintf("http://192.0.2.%d:80", i+1), Weight: 1}
	}
	return &gateonv1.Service{Id: id, HealthCheckType: gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP,
		HealthCheckPath: "/healthz", WeightedTargets: targets}
}

// TestHealthChecksRunTargetsConcurrently is DP-N8. Every target of a route was
// checked one after another, each with a 5 s timeout and two failures to
// eject, so k blackholed targets took about k*10 s to leave rotation -- and
// past three of them a tick outran the 15 s interval. The checks of one tick
// now overlap.
func TestHealthChecksRunTargetsConcurrently(t *testing.T) {
	const k = 4
	ph := proxyFor(t, blackholedService("blackholed", k))
	bh := newBlackhole(k, time.Second)

	start := time.Now()
	ph.checkAll(t.Context(), &http.Client{Transport: bh})
	if got := bh.max.Load(); got < k {
		t.Fatalf("at most %d of %d target checks were in flight at once (tick took %v); "+
			"k blackholed targets take k timeouts to check", got, k, time.Since(start).Round(time.Millisecond))
	}
	ph.checkAll(t.Context(), &http.Client{Transport: bh})
	for _, s := range ph.GetStats() {
		if s.Alive {
			t.Errorf("%s still alive after two failed ticks", s.URL)
		}
	}
}

// TestHealthChecksAreBoundedPerTick: the overlap is bounded, so a route with
// hundreds of targets does not open hundreds of connections at once.
func TestHealthChecksAreBoundedPerTick(t *testing.T) {
	const k = 3 * healthCheckWorkers
	ph := proxyFor(t, blackholedService("many", k))
	bh := newBlackhole(healthCheckWorkers, time.Second)

	ph.checkAll(t.Context(), &http.Client{Transport: bh})
	if got := bh.max.Load(); got != healthCheckWorkers {
		t.Fatalf("%d checks were in flight at once, want exactly the bound %d", got, healthCheckWorkers)
	}
}
