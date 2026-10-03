// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// funnelChains are the three handlers a request can take through the real
// entrypoint chain: a route that reaches the backend, a route whose IP filter
// refuses the client, and no route at all.
type funnelChains struct{ open, filtered, unrouted http.Handler }

func buildFunnelChains(t *testing.T) funnelChains {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/err") {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	global := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	if err := services.Update(t.Context(), &gateonv1.Service{
		Id: "svc", WeightedTargets: []*gateonv1.Target{{Url: upstream.URL, Weight: 1}},
	}); err != nil {
		t.Fatalf("service: %v", err)
	}
	if err := mws.Update(t.Context(), &gateonv1.Middleware{Id: "deny", Name: "deny", Type: "ipfilter",
		Config: map[string]string{"deny_list": "203.0.113.9"}}); err != nil {
		t.Fatalf("middleware: %v", err)
	}
	ep := &gateonv1.EntryPoint{Id: "web", Name: "web", Address: ":8080"}
	deps := &Deps{GlobalStore: global}
	route := func(rt *gateonv1.Route) http.Handler {
		ph := proxy.NewProxyHandler(rt, services)
		t.Cleanup(ph.Close)
		return middleware.Chain(entrypointChain(t.Context(), ep, deps)...)(
			router.ApplyRouteMiddlewares(ph, rt, nil, mws, global, nil, nil))
	}
	return funnelChains{
		open:     route(&gateonv1.Route{Id: "r-ok", Name: "r-ok", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http"}),
		filtered: route(&gateonv1.Route{Id: "r-blk", Name: "r-blk", ServiceId: "svc", Rule: "PathPrefix(`/`)", Type: "http", Middlewares: []string{"deny"}}),
		unrouted: middleware.Chain(entrypointChain(t.Context(), ep, deps)...)(http.NotFoundHandler()),
	}
}

func serveFunnel(t *testing.T, h http.Handler, path, remoteAddr string, wantStatus int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com"+path, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("GET %s from %s = %d, want %d", path, remoteAddr, rec.Code, wantStatus)
	}
}

func funnelNow(t *testing.T) telemetry.MitigationFunnel {
	t.Helper()
	snap, err := telemetry.CollectMetricsSnapshot(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return snap.MitigationFunnel
}

// TestTheFunnelCountsEachRequestOnceAndAnIPFilterDenyAsRefused is T13. Ten
// requests through the real entrypoint and route chains: six reach the
// backend (two of them answered 500 there), three are refused by a route's IP
// filter, one matches no route.
//
// The funnel summed gateon_requests_total over every label, and a proxied
// request is recorded under its entrypoint's and its route's, so it showed 19
// requests; and the IP filter keeps no counter, so its three refusals were
// "Allowed", making 19 allowed of 19.
func TestTheFunnelCountsEachRequestOnceAndAnIPFilterDenyAsRefused(t *testing.T) {
	c := buildFunnelChains(t)
	before := funnelNow(t)

	for range 4 {
		serveFunnel(t, c.open, "/page", "198.51.100.23:5000", http.StatusOK)
	}
	for range 2 {
		serveFunnel(t, c.open, "/err", "198.51.100.23:5000", http.StatusInternalServerError)
	}
	for range 3 {
		serveFunnel(t, c.filtered, "/page", "203.0.113.9:5000", http.StatusForbidden)
	}
	serveFunnel(t, c.unrouted, "/nowhere", "198.51.100.23:5000", http.StatusNotFound)

	after := funnelNow(t)
	got := map[string]float64{
		"ingress":       after.HTTPIngress - before.HTTPIngress,
		"allowed":       after.Allowed - before.Allowed,
		"refused":       after.Refused - before.Refused,
		"answered":      after.Answered - before.Answered,
		"server errors": after.ServerErrors - before.ServerErrors,
	}
	want := map[string]float64{
		"ingress": 10, "allowed": 6, "refused": 4, "answered": 0, "server errors": 2,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: +%v, want +%v (all: %v)", k, got[k], w, got)
		}
	}
}
