// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestRouteStatsShowAnOpenBreaker: once a route's circuit breaker opened, the
// gateway answered 503 without reaching the backend while /v1/routes/stats --
// what the Circuit Breaker page shows -- still said CLOSED for its target,
// because a row's state came from the health check alone. The row now carries
// the breaker's state. A breaker removed from the route stops being reported.
func TestRouteStatsShowAnOpenBreaker(t *testing.T) {
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(backend.Close)

	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	ctx := t.Context()
	mustSave(t, services.Update(ctx, &gateonv1.Service{Id: "cb-svc", Name: "cb-svc",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}}}))
	mustSave(t, mws.Update(ctx, &gateonv1.Middleware{Id: "cb", Name: "cb", Type: "circuit_breaker",
		Config: map[string]string{"min_requests": "3", "error_threshold": "0.5", "sleep_window": "1h"}}))
	rt := &gateonv1.Route{Id: "cb-route", Name: "cb-route", ServiceId: "cb-svc",
		Rule: "PathPrefix(`/`)", Middlewares: []string{"cb"}}
	mustSave(t, routes.Update(ctx, rt))
	cache := NewProxyCache(routes, services, mws, nil,
		config.NewGlobalRegistry(filepath.Join(dir, "global.json")), nil, nil)
	t.Cleanup(cache.Purge)

	h := cache.GetOrCreate(rt)
	if h == nil {
		t.Fatal("the route did not build")
	}
	for range 3 {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://gw.test/", nil))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gw.test/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("setup: after three 500s the breaker did not open (status %d)", rec.Code)
	}

	stats := cache.GetRouteStats("cb-route")
	if len(stats) != 1 || stats[0].CircuitState != "OPEN" || stats[0].Breaker != "OPEN" {
		t.Fatalf("route stats with the breaker open = %+v, want the target OPEN with breaker OPEN", stats)
	}

	rt.Middlewares = nil
	mustSave(t, routes.Update(ctx, rt))
	cache.InvalidateRoute("cb-route")
	if stats := cache.GetRouteStats("cb-route"); len(stats) != 1 || stats[0].CircuitState != "CLOSED" || stats[0].Breaker != "" {
		t.Fatalf("with the breaker removed from the route, stats = %+v, want CLOSED and no breaker", stats)
	}
}

func mustSave(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
