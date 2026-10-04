// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// applyFixService is an ApiService over file-backed stores with two routes,
// eBPF present but disabled (a Holder with no manager, as on a default
// install), and a telemetry store.
func applyFixService(t *testing.T) (*ApiService, *config.RouteRegistry, *config.MiddlewareRegistry, *config.GlobalRegistry) {
	t.Helper()
	dir := t.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	globals := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	for _, id := range []string{"r1", "r2"} {
		if err := routes.Update(t.Context(), &gateonv1.Route{Id: id, Name: id, Middlewares: []string{"keep"}}); err != nil {
			t.Fatalf("seed route: %v", err)
		}
	}
	if err := telemetry.InitPathStatsStore(filepath.Join(dir, "fix.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { telemetry.ClosePathStatsStore(t.Context()) })
	svc := NewApiService(ApiServiceConfig{
		Routes: routes, Middlewares: mws, Globals: globals,
		EntryPoints: config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json")),
		Services:    config.NewServiceRegistry(filepath.Join(dir, "services.json")),
		EbpfManager: ebpf.NewHolder(nil),
	})
	return svc, routes, mws, globals
}

// TestWAFBlockFixBlocksForABoundedTimeAndSaysOnlyThat is truth NEW-7: the
// waf_block "Apply fix" answered "blocked via middleware and shunned at XDP
// level" with eBPF disabled, and each application added another block-ip-*
// ipfilter to every route, forever: no expiry, no bound, and outside the
// block list Remove Mitigation manages. The fix now writes one bounded entry
// to the block list every entrypoint enforces, leaves the routes alone, and
// says what it did.
func TestWAFBlockFixBlocksForABoundedTimeAndSaysOnlyThat(t *testing.T) {
	svc, routes, mws, _ := applyFixService(t)
	ctx := t.Context()
	const ip = "10.77.1.5"
	var resp *gateonv1.ApplyRecommendationResponse
	for range 2 {
		var err error
		resp, err = svc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{AnomalyType: "waf_block", Source: ip})
		if err != nil || !resp.GetSuccess() {
			t.Fatalf("apply fix: err=%v resp=%v", err, resp)
		}
	}
	if strings.Contains(resp.GetMessage(), "XDP") || strings.Contains(resp.GetMessage(), "kernel") ||
		strings.Contains(resp.GetMessage(), "middleware") {
		t.Errorf("message claims what did not happen (eBPF is off, no middleware is the mechanism): %q", resp.GetMessage())
	}
	for _, rt := range routes.List(ctx) {
		if len(rt.GetMiddlewares()) != 1 {
			t.Errorf("route %s middlewares = %v, want only its own: the fix must not grow every chain", rt.GetId(), rt.GetMiddlewares())
		}
	}
	for _, m := range mws.List(ctx) {
		if strings.HasPrefix(m.GetId(), "block-ip-") {
			t.Errorf("the fix created middleware %s; the block list is the mechanism", m.GetId())
		}
	}
	if !identity.AddressBlocked(ip) {
		t.Fatalf("%s is not refused by the entrypoints' block decision after the fix", ip)
	}
	assertBlockExpiresWithin(t, ip, recommendationBlockDuration)
}

// assertBlockExpiresWithin finds ip's block and checks it lapses on its own,
// no later than d from now.
func assertBlockExpiresWithin(t *testing.T, ip string, d time.Duration) {
	t.Helper()
	list, _ := telemetry.GetIPMitigations(t.Context(), 100, 0)
	for _, m := range list {
		if m.IP != ip {
			continue
		}
		if m.ExpiresAt == nil {
			t.Fatalf("the block on %s never expires", ip)
		}
		if left := time.Until(*m.ExpiresAt); left <= 0 || left > d+time.Minute {
			t.Fatalf("the block on %s lapses in %v, want within %v", ip, left, d)
		}
		return
	}
	t.Fatalf("no block recorded for %s", ip)
}

// TestWAFHardeningFixTurnsAuditOnlyOffAndSaysWhatChanged is the rest of
// NEW-7: the security_vulnerability fix set the global category booleans,
// which ADR 0044 says the global WAF ignores, and answered "enabled ... core
// protections and OWASP CRS" while an audit-only WAF stayed audit-only and
// blocked nothing.
func TestWAFHardeningFixTurnsAuditOnlyOffAndSaysWhatChanged(t *testing.T) {
	svc, _, _, globals := applyFixService(t)
	ctx := t.Context()
	if err := globals.Update(ctx, &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, AuditOnly: true}}); err != nil {
		t.Fatalf("seed global: %v", err)
	}
	resp, err := svc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{AnomalyType: "security_vulnerability"})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("apply fix: err=%v resp=%v", err, resp)
	}
	if w := globals.Get(ctx).GetWaf(); !w.GetEnabled() || w.GetAuditOnly() {
		t.Fatalf("after the fix the global WAF is enabled=%v audit_only=%v, want on and blocking", w.GetEnabled(), w.GetAuditOnly())
	}
	if !strings.Contains(resp.GetMessage(), "audit-only") || strings.Contains(resp.GetMessage(), "OWASP CRS") {
		t.Errorf("message does not say what changed: %q", resp.GetMessage())
	}
	resp, _ = svc.ApplyRecommendation(ctx, &gateonv1.ApplyRecommendationRequest{AnomalyType: "security_vulnerability"})
	if !strings.Contains(resp.GetMessage(), "nothing changed") {
		t.Errorf("applied to a WAF already blocking, the message claims a change: %q", resp.GetMessage())
	}
}
