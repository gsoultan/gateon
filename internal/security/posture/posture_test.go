// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package posture

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func mw(id, typ string, cfg map[string]string) *gateonv1.Middleware {
	return &gateonv1.Middleware{Id: id, Type: typ, Config: cfg}
}

func httpRoute(id string, mws ...string) *gateonv1.Route {
	return &gateonv1.Route{Id: id, Type: "http", Middlewares: mws}
}

func index(mws ...*gateonv1.Middleware) map[string]*gateonv1.Middleware {
	out := map[string]*gateonv1.Middleware{}
	for _, m := range mws {
		out[m.GetId()] = m
	}
	return out
}

// TestCoverageReadsTheWAFThatRuns is T12: a route-level audit-only WAF
// replaces the enforcing global one on that route, and an audit-only global
// WAF blocks nothing anywhere. Both used to read as "protecting".
func TestCoverageReadsTheWAFThatRuns(t *testing.T) {
	enforcingGlobal := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true}}
	auditGlobal := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, AuditOnly: true, UseCrs: true}}
	mws := index(
		mw("w-audit", "waf", map[string]string{"audit_only": "true"}),
		mw("w-one", "waf", map[string]string{"audit_only": "1"}),
		mw("w-plain", "waf", map[string]string{}),
		mw("w-enforce", "waf", map[string]string{"audit_only": "false"}),
		mw("w-empty", "waf", map[string]string{"audit_only": ""}),
	)
	auditNoCRS := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, AuditOnly: true}}
	cases := []struct {
		name   string
		global *gateonv1.GlobalConfig
		route  *gateonv1.Route
		want   Mode
	}{
		{"global enforce, no route WAF", enforcingGlobal, httpRoute("r"), ModeEnforce},
		{"global enforce, route WAF audit-only", enforcingGlobal, httpRoute("r", "w-audit"), ModeDetect},
		{"audit_only spelled 1", enforcingGlobal, httpRoute("r", "w-one"), ModeDetect},
		{"global audit-only, no route WAF", auditGlobal, httpRoute("r"), ModeDetect},
		{"global audit-only with CRS, route WAF inherits it", auditGlobal, httpRoute("r", "w-plain"), ModeDetect},
		{"route WAF says enforce over an audit-only global", auditGlobal, httpRoute("r", "w-enforce"), ModeEnforce},
		{"one enforcing WAF of two refuses", auditGlobal, httpRoute("r", "w-audit", "w-enforce"), ModeEnforce},
		// ADR 0044: a route WAF inherits what it leaves unset from any enabled
		// global WAF, not only one with CRS on, and an empty value is unset.
		{"global audit-only without CRS, route WAF inherits it", auditNoCRS, httpRoute("r", "w-plain"), ModeDetect},
		{"an empty audit_only inherits", auditNoCRS, httpRoute("r", "w-empty"), ModeDetect},
		{"no WAF at all", &gateonv1.GlobalConfig{}, httpRoute("r"), ModeOff},
		{"route WAF with the global off", &gateonv1.GlobalConfig{}, httpRoute("r", "w-plain"), ModeEnforce},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cov := Coverage(Config{Global: tc.global, Routes: []*gateonv1.Route{tc.route}, Middlewares: mws})
			got := map[Mode]int{ModeEnforce: cov.Enforcing, ModeDetect: cov.Detecting, ModeOff: cov.Off}
			if cov.Total != 1 || got[tc.want] != 1 {
				t.Fatalf("coverage = %+v, want the one route counted as %s", cov, tc.want)
			}
		})
	}
}

// TestCoverageSkipsWhatNoHTTPMiddlewareRuns: a disabled route serves nothing
// and a TCP/UDP route runs no WAF, so neither is a route the WAF misses.
func TestCoverageSkipsWhatNoHTTPMiddlewareRuns(t *testing.T) {
	routes := []*gateonv1.Route{
		{Id: "off", Type: "http", Disabled: true},
		{Id: "tcp", Type: "tcp"},
		{Id: "udp", Type: "UDP"},
		{Id: "grpc", Type: "grpc"},
	}
	cov := Coverage(Config{Global: &gateonv1.GlobalConfig{}, Routes: routes})
	if cov.Total != 1 || cov.Off != 1 {
		t.Fatalf("coverage = %+v, want only the grpc route, unprotected", cov)
	}
}

// TestSignatureScanningFollowsFileSecurity is T4: the signature engine runs
// only inside a file_security middleware, so with none nothing is scanned.
func TestSignatureScanningFollowsFileSecurity(t *testing.T) {
	mws := index(
		mw("fs-default", "file_security", map[string]string{}),
		mw("fs-off", "file_security", map[string]string{"enable_signature_scan": "false"}),
		mw("fs-bad", "file_security", map[string]string{"enable_signature_scan": "yes please"}),
		mw("waf", "waf", map[string]string{}),
	)
	cases := []struct {
		name  string
		route *gateonv1.Route
		want  int
	}{
		{"no middleware", httpRoute("r"), 0},
		{"another middleware", httpRoute("r", "waf"), 0},
		{"file_security, scan left at its default", httpRoute("r", "fs-default"), 1},
		{"file_security, scan off", httpRoute("r", "fs-off"), 0},
		{"malformed value refuses the middleware", httpRoute("r", "fs-bad"), 0},
		{"id with stray space, as routes store it", httpRoute("r", " fs-default "), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cov := Coverage(Config{Global: &gateonv1.GlobalConfig{}, Routes: []*gateonv1.Route{tc.route}, Middlewares: mws})
			if cov.SignatureScanning != tc.want {
				t.Fatalf("SignatureScanning = %d, want %d", cov.SignatureScanning, tc.want)
			}
		})
	}
}

// TestBotCoverageCountsTheRoutesThatCarryIt: the global bot settings are
// defaults for the bot_management middleware; a route is covered only by
// carrying one.
func TestBotCoverageCountsTheRoutesThatCarryIt(t *testing.T) {
	mws := index(mw("bots", "bot_management", nil), mw("waf", "waf", nil))
	global := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{BotManagement: &gateonv1.BotManagementConfig{Enabled: true}}}
	cov := Coverage(Config{Global: global, Middlewares: mws,
		Routes: []*gateonv1.Route{httpRoute("a", "bots"), httpRoute("b", "waf"), httpRoute("c")}})
	if cov.BotManagement != 1 {
		t.Fatalf("BotManagement = %d, want 1 (only route a carries the middleware)", cov.BotManagement)
	}
}

// allCategoriesOff is a route WAF config with every attack-category switch off.
func allCategoriesOff() map[string]string {
	cfg := map[string]string{}
	for _, k := range AttackCategoryKeys {
		cfg[k] = "false"
	}
	return cfg
}

// TestWAFWithEveryCategoryOffEarnsNoBlockingCredit is truth NEW-13: a route
// WAF with every attack category switched off was counted as blocking and
// earned full WAF credit, while SQLi, XSS, LFI and RCE probes reached the
// backend. It blocks none of the attacks the control is about, so it is
// counted apart and earns nothing.
func TestWAFWithEveryCategoryOffEarnsNoBlockingCredit(t *testing.T) {
	oneOn := allCategoriesOff()
	oneOn["xss"] = "true"
	mws := index(mw("none", "waf", allCategoriesOff()), mw("xss-only", "waf", oneOn))
	global := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true}}
	cases := []struct {
		name       string
		route      *gateonv1.Route
		enforcing  int
		catsOff    int
		wantCredit float64
	}{
		{"every category off", httpRoute("r", "none"), 0, 1, 0},
		{"one category left on", httpRoute("r", "xss-only"), 1, 0, 1},
		{"a second WAF that runs categories", httpRoute("r", "none", "xss-only"), 1, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{Global: global, Routes: []*gateonv1.Route{tc.route}, Middlewares: mws}
			cov := Coverage(c)
			if cov.Enforcing != tc.enforcing || cov.CategoriesOff != tc.catsOff {
				t.Fatalf("coverage = %+v, want enforcing %d, categoriesOff %d", cov, tc.enforcing, tc.catsOff)
			}
			if got := controlByID(t, Compute(c), "waf").Credit; got != tc.wantCredit {
				t.Errorf("WAF credit = %v, want %v", got, tc.wantCredit)
			}
		})
	}
}

// TestRateLimitCoverageCountsTheRoutesThatCarryIt: what replaces the
// advisory's removed DoS-switch check (NEW-6) is counted on the routes that
// carry a ratelimit or inflightreq middleware, once per route.
func TestRateLimitCoverageCountsTheRoutesThatCarryIt(t *testing.T) {
	mws := index(mw("rl", "ratelimit", nil), mw("inflight", "inflightreq", nil), mw("waf", "waf", nil))
	cov := Coverage(Config{Global: &gateonv1.GlobalConfig{}, Middlewares: mws, Routes: []*gateonv1.Route{
		httpRoute("a", "rl"), httpRoute("b", "inflight"), httpRoute("c", "rl", "inflight"), httpRoute("d", "waf"),
	}})
	if cov.RateLimited != 3 {
		t.Fatalf("RateLimited = %d, want 3 (routes a, b and c; d carries only a WAF)", cov.RateLimited)
	}
}

func controlByID(t *testing.T, s Score, id string) Control {
	t.Helper()
	for _, c := range s.Controls {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no control %q in %+v", id, s.Controls)
	return Control{}
}

// TestScoreWithNothingConfiguredIsNotPerfect is T11: the posture read 100%
// on an install with no protection switched on.
func TestScoreWithNothingConfiguredIsNotPerfect(t *testing.T) {
	s := Compute(Config{
		Global:              &gateonv1.GlobalConfig{},
		Routes:              []*gateonv1.Route{httpRoute("r")},
		EntryPoints:         []*gateonv1.EntryPoint{{Id: "web", Address: ":80"}},
		ManagementWorldOpen: true,
	})
	if s.Percent != 10 {
		t.Fatalf("percent = %d, want 10 (only the half-open management listener earns anything): %+v", s.Percent, s.Controls)
	}
	if c := controlByID(t, s, "waf"); c.State != StateOff {
		t.Fatalf("waf control = %+v, want off", c)
	}
}

// TestScoreFullyConfigured: every control in effect is 100.
func TestScoreFullyConfigured(t *testing.T) {
	s := Compute(Config{
		Global: &gateonv1.GlobalConfig{
			Waf:              &gateonv1.WafConfig{Enabled: true},
			AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true},
			Audit:            &gateonv1.AuditConfig{Enabled: true, SignEntries: true},
		},
		Routes:      []*gateonv1.Route{httpRoute("r")},
		EntryPoints: []*gateonv1.EntryPoint{{Id: "web", Address: ":443", Tls: &gateonv1.TlsConfig{Enabled: true}}},
	})
	if s.Percent != 100 {
		t.Fatalf("percent = %d, want 100: %+v", s.Percent, s.Controls)
	}
	total := 0
	for _, c := range s.Controls {
		total += c.Weight
	}
	if total != 100 {
		t.Fatalf("weights sum to %d, want 100", total)
	}
}

// TestScoreAuditOnlyWAFEarnsHalf: detecting is not blocking.
func TestScoreAuditOnlyWAFEarnsHalf(t *testing.T) {
	s := Compute(Config{
		Global: &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, AuditOnly: true}},
		Routes: []*gateonv1.Route{httpRoute("a"), httpRoute("b")},
	})
	c := controlByID(t, s, "waf")
	if c.Credit != 0.5 || c.State != StatePartial {
		t.Fatalf("waf control = %+v, want half credit, partial", c)
	}
}

// TestScoreTLS weighs only entrypoints another host can reach, and counts a
// plaintext one that redirects to HTTPS as the listener serves it.
func TestScoreTLS(t *testing.T) {
	tlsOn := &gateonv1.TlsConfig{Enabled: true}
	cases := []struct {
		name     string
		redirect bool
		eps      []*gateonv1.EntryPoint
		want     float64
	}{
		{"loopback only", false, []*gateonv1.EntryPoint{{Address: "127.0.0.1:80"}, {Address: "[::1]:81"}, {Address: "localhost:82"}}, 1},
		{"one of two encrypts", false, []*gateonv1.EntryPoint{{Address: ":80"}, {Address: ":443", Tls: tlsOn}}, 0.5},
		{"plaintext redirects to the TLS one", true, []*gateonv1.EntryPoint{{Address: ":80"}, {Address: ":443", Tls: tlsOn}}, 1},
		{"redirect with nowhere to go", true, []*gateonv1.EntryPoint{{Address: ":80"}}, 0},
		{"udp is not weighed", false, []*gateonv1.EntryPoint{{Address: ":53", Type: gateonv1.EntryPoint_UDP}}, 1},
		{"http3 is encrypted", false, []*gateonv1.EntryPoint{{Address: ":443", Type: gateonv1.EntryPoint_HTTP3}}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &gateonv1.GlobalConfig{Tls: &gateonv1.TlsConfig{AutoRedirect: tc.redirect}}
			c := controlByID(t, Compute(Config{Global: g, EntryPoints: tc.eps}), "tls")
			if c.Credit != tc.want {
				t.Fatalf("tls credit = %v, want %v (%s)", c.Credit, tc.want, c.Detail)
			}
		})
	}
}

// TestScoreManagementAndAudit covers the remaining controls' three states.
func TestScoreManagementAndAudit(t *testing.T) {
	g := &gateonv1.GlobalConfig{}
	if c := controlByID(t, Compute(Config{Global: g, PublicManagement: true, ManagementWorldOpen: true}), "management"); c.Credit != 0 {
		t.Fatalf("public management credit = %v, want 0", c.Credit)
	}
	if c := controlByID(t, Compute(Config{Global: g}), "management"); c.Credit != 1 {
		t.Fatalf("restricted management credit = %v, want 1", c.Credit)
	}
	unsigned := &gateonv1.GlobalConfig{Audit: &gateonv1.AuditConfig{Enabled: true}}
	if c := controlByID(t, Compute(Config{Global: unsigned}), "audit"); c.Credit != 0.5 {
		t.Fatalf("unsigned audit credit = %v, want 0.5", c.Credit)
	}
}
