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

// TestTargetCountsSurviveARebuild: a target's request and error counts lived in
// the route's handler, and every rebuild started them at zero -- the governor's
// purge above 80% host memory, and any service save, including one for another
// service. A backend failing every request read 0 errors on the dashboard after
// each one. The rebuilt handler now starts from its predecessor's counts.
func TestTargetCountsSurviveARebuild(t *testing.T) {
	dir := t.TempDir()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(backend.Close)
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mustSave(t, services.Update(t.Context(), &gateonv1.Service{Id: "carry-svc", Name: "carry-svc",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}}}))
	rt := &gateonv1.Route{Id: "carry-route", Name: "carry-route", ServiceId: "carry-svc", Rule: "PathPrefix(`/`)"}
	mustSave(t, routes.Update(t.Context(), rt))
	cache := NewProxyCache(routes, services, config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json")),
		nil, config.NewGlobalRegistry(filepath.Join(dir, "global.json")), nil, nil)
	t.Cleanup(cache.Purge)

	serve := func(n int) {
		h := cache.GetOrCreate(rt)
		for range n {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://gw.test/", nil))
		}
	}
	counts := func() (uint64, uint64) {
		s := cache.GetRouteStats("carry-route")
		if len(s) != 1 {
			t.Fatalf("stats = %+v, want one target", s)
		}
		return s[0].RequestCount, s[0].ErrorCount
	}

	serve(4)
	cache.Purge() // what the governor does under memory pressure
	if req, errs := counts(); req != 4 || errs != 4 {
		t.Fatalf("after a purge the target reads %d requests, %d errors; want 4 and 4", req, errs)
	}
	serve(2)
	cache.InvalidateRoute("carry-route") // what a service save does to its routes
	if req, errs := counts(); req != 6 || errs != 6 {
		t.Fatalf("after an invalidation the target reads %d requests, %d errors; want 6 and 6", req, errs)
	}
}
