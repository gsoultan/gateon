// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// cacheInvalidator is the invalidator the gateway hands the API service,
// reduced to the proxy cache: routes are dropped from it, and TLS and WAF
// invalidation have nothing to reach here.
type cacheInvalidator struct{ *ProxyCache }

func (cacheInvalidator) InvalidateTLS() {}
func (cacheInvalidator) InvalidateWAF() {}

// TestWAFHardeningFixReachesCachedChains is review-3 F1: the
// security_vulnerability "Apply fix" saved the global WAF with audit-only off
// and answered "it now refuses what it matches", but invalidated nothing. The
// router builds the global WAF into each route's chain when it builds the
// chain, so every cached route kept the audit-only WAF and forwarded every
// attack until some unrelated edit rebuilt it. The attack is sent through the
// cache that served it before the fix, with no invalidation but the fix's own.
func TestWAFHardeningFixReachesCachedChains(t *testing.T) {
	dir := t.TempDir()
	// The global WAF's audit log goes under the data directory.
	t.Setenv("GATEON_DATA_DIR", dir)
	ctx := t.Context()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(backend.Close)
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	mustSave(t, services.Update(ctx, &gateonv1.Service{Id: "svc", Name: "svc",
		WeightedTargets: []*gateonv1.Target{{Url: backend.URL, Weight: 1}}}))
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	mustSave(t, globals.Update(ctx, &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, AuditOnly: true, UseCrs: true}}))
	rt := &gateonv1.Route{Id: "r1", Name: "r1", ServiceId: "svc", Rule: "PathPrefix(`/`)"}
	mustSave(t, routes.Update(ctx, rt))
	cache := NewProxyCache(routes, services, mws, nil, globals, nil, nil)
	t.Cleanup(cache.Purge)
	attack := func() int {
		rec := httptest.NewRecorder()
		cache.GetOrCreate(rt).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
			"http://app.example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E%20union%20select%201,2", nil))
		return rec.Code
	}
	if code := attack(); code != http.StatusOK {
		t.Fatalf("audit-only global WAF answered the attack %d, want it forwarded (200): the test proves nothing", code)
	}

	svc := api.NewApiService(api.ApiServiceConfig{Routes: routes, Middlewares: mws, Globals: globals, Services: services,
		EntryPoints: config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json")), Invalidator: cacheInvalidator{cache}})
	resp, err := svc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{AnomalyType: "security_vulnerability"})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("apply fix: err=%v resp=%v", err, resp)
	}
	if globals.Get(ctx).GetWaf().GetAuditOnly() {
		t.Fatal("the fix reported success and left audit-only on")
	}
	if code := attack(); code != http.StatusForbidden {
		t.Fatalf("after the fix said the WAF now refuses what it matches, the cached route answered the attack %d, want 403", code)
	}
}
