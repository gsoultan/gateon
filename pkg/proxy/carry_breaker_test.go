// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestInheritStartsFromThePredecessorsCounts: a rebuilt handler starts each
// target it keeps from the counts its predecessor had, and a target new to it
// from nothing.
func TestInheritStartsFromThePredecessorsCounts(t *testing.T) {
	urls := namedBackends(t, "kept")
	before := proxyFor(t, &gateonv1.Service{Id: "carry", WeightedTargets: []*gateonv1.Target{{Url: urls["kept"], Weight: 1}}})
	sequence(t, before, 3)

	extra := namedBackends(t, "new")["new"]
	after := proxyFor(t, &gateonv1.Service{Id: "carry", WeightedTargets: []*gateonv1.Target{
		{Url: urls["kept"], Weight: 1}, {Url: extra, Weight: 1},
	}})
	after.Inherit(before.Carry())
	if s := statsFor(t, after, urls["kept"]); s.RequestCount != 3 {
		t.Fatalf("the kept target starts at %d requests, want its predecessor's 3", s.RequestCount)
	}
	if s := statsFor(t, after, extra); s.RequestCount != 0 {
		t.Fatalf("a target the predecessor did not have starts at %d requests, want 0", s.RequestCount)
	}
}

var breakerRuns atomic.Int64

// TestARowReportsItsRoutesBreaker: with a breaker key set, every target row
// carries the breaker's state, and an open breaker makes a healthy target read
// OPEN. Without one, the rows are the health check's alone.
func TestARowReportsItsRoutesBreaker(t *testing.T) {
	key := fmt.Sprintf("breaker-row-%d", breakerRuns.Add(1))
	cb := middleware.CircuitBreaker(middleware.CircuitBreakerConfig{
		ErrorThreshold: 0.5, MinRequests: 1, RouteID: key, Key: key,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	cb.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	urls := namedBackends(t, "healthy")
	ph := proxyFor(t, &gateonv1.Service{Id: key, WeightedTargets: []*gateonv1.Target{{Url: urls["healthy"], Weight: 1}}})
	if s := statsFor(t, ph, urls["healthy"]); s.CircuitState != CircuitClosed || s.Breaker != "" {
		t.Fatalf("with no breaker key the row reads %s/%q, want CLOSED and no breaker", s.CircuitState, s.Breaker)
	}
	ph.SetCircuitBreakerKey(key)
	if s := statsFor(t, ph, urls["healthy"]); s.CircuitState != CircuitOpen || s.Breaker != CircuitOpen || !s.Alive {
		t.Fatalf("behind an open breaker the row reads %s/%q alive=%v, want OPEN/OPEN, still alive",
			s.CircuitState, s.Breaker, s.Alive)
	}
}
