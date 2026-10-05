// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestBaseHandlerRefusesAmbiguousPaths is DP-F8 where a client meets it. A
// path Tomcat or IIS resolves to a different resource than the router does is
// answered 400 before route selection and before any route middleware -- the
// WAF included -- so neither runs against a path the backend will not serve.
func TestBaseHandlerRefusesAmbiguousPaths(t *testing.T) {
	var proxied atomic.Int32
	proxy := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	routes := &mockRouteStoreWithRoutes{routes: []*gateonv1.Route{
		{Id: "catch-all", Rule: "PathPrefix(`/`)"},
	}}
	handler := CreateBaseHandler(http.NotFoundHandler(), BaseHandlerDeps{
		ProxyHandler: proxy, RouteStore: routes,
		GlobalReg: &mockGlobalReg{config: &gateonv1.GlobalConfig{}},
	}, nil, http.NewServeMux())

	for _, p := range []string{"/public/..;/admin", "/public/.;/admin", `/public\..\admin`, "/public%5Cadmin"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q answered %d, want 400", p, rec.Code)
		}
	}
	if n := proxied.Load(); n != 0 {
		t.Errorf("%d ambiguous requests reached the route", n)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/cars;color=red", nil))
	if rec.Code != http.StatusOK || proxied.Load() != 1 {
		t.Errorf("an ordinary path parameter answered %d (proxied %d), want 200 via the route",
			rec.Code, proxied.Load())
	}
}
