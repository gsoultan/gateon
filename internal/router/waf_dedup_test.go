// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func init() {
	// The WAF middleware needs its rules store; an in-memory one is enough.
	_ = waf.InitStore("sqlite::memory:")
}

// --- minimal store fakes (only Get is exercised by ApplyRouteMiddlewares) ----

type fakeMWStore struct {
	m map[string]*gateonv1.Middleware
}

func (f fakeMWStore) Get(_ context.Context, id string) (*gateonv1.Middleware, bool) {
	mw, ok := f.m[id]
	return mw, ok
}
func (f fakeMWStore) List(context.Context) []*gateonv1.Middleware { return nil }
func (f fakeMWStore) ListPaginated(context.Context, int32, int32, string) ([]*gateonv1.Middleware, int32) {
	return nil, 0
}
func (f fakeMWStore) All(context.Context) map[string]*gateonv1.Middleware { return f.m }
func (f fakeMWStore) Update(context.Context, *gateonv1.Middleware) error  { return nil }
func (f fakeMWStore) Delete(context.Context, string) error                { return nil }

type fakeGlobalStore struct{ cfg *gateonv1.GlobalConfig }

func (f fakeGlobalStore) Get(context.Context) *gateonv1.GlobalConfig { return f.cfg }
func (f fakeGlobalStore) GetCertificate(string) (*gateonv1.Certificate, bool) {
	return nil, false
}
func (f fakeGlobalStore) Update(context.Context, *gateonv1.GlobalConfig) error { return nil }
func (f fakeGlobalStore) ConfigFileExists() bool                               { return true }

// TestApplyRouteMiddlewares_GlobalWAFDeduplication is the regression guard for
// the double-inspection the router used to allow: when the gateway-wide WAF is
// enabled, a route that also attached its own "waf" middleware ran the engine
// twice — twice the per-request cost and two threat records for one block.
//
// The tell is an audit-only per-route WAF sitting under a blocking global WAF.
// With de-duplication the route's own WAF is the only one that runs, so its
// audit-only intent is honoured and the attack is detected-not-blocked (200).
// Without it the global WAF also runs and blocks the same request (403), which
// both proves the double-run and violates the operator's explicit override.
func TestApplyRouteMiddlewares_GlobalWAFDeduplication(t *testing.T) {
	const sqli = "/?id=1%27%20OR%20%271%27%3D%271%20--%20"

	mwStore := fakeMWStore{m: map[string]*gateonv1.Middleware{
		"waf-audit": {Id: "waf-audit", Type: "waf", Config: map[string]string{
			"audit_only": "true", "sqli": "true", "xss": "true",
		}},
		"waf-block": {Id: "waf-block", Type: "waf", Config: map[string]string{
			"audit_only": "false", "sqli": "true", "xss": "true",
		}},
	}}
	// Global WAF enabled and blocking.
	gStore := fakeGlobalStore{cfg: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, ParanoiaLevel: 1},
	}}

	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	send := func(h http.Handler, url string) int {
		req := httptest.NewRequest(http.MethodGet, url, strings.NewReader(""))
		// Neutralise the reputation rules so the SQLi rule alone decides the
		// verdict; the payload is what must be caught, not the client score.
		req.Header.Set("X-Gateon-Test-Reputation", "100")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	tests := []struct {
		name        string
		route       *gateonv1.Route
		url         string
		expect      int
		explanation string
	}{
		{
			name:        "audit-only route WAF wins over blocking global WAF",
			route:       &gateonv1.Route{Id: "r-audit", Middlewares: []string{"waf-audit"}},
			url:         sqli,
			expect:      http.StatusOK,
			explanation: "the route's audit-only WAF is the only one that runs; a 403 here means the global WAF also ran (double inspection)",
		},
		{
			name:        "audit-only route still passes benign traffic",
			route:       &gateonv1.Route{Id: "r-audit2", Middlewares: []string{"waf-audit"}},
			url:         "/?q=hello",
			expect:      http.StatusOK,
			explanation: "benign request through the override",
		},
		{
			name:        "route with no WAF is protected by the global WAF",
			route:       &gateonv1.Route{Id: "r-none"},
			url:         sqli,
			expect:      http.StatusForbidden,
			explanation: "security by default: no per-route WAF means the global one applies",
		},
		{
			name:        "route with a blocking WAF override still blocks",
			route:       &gateonv1.Route{Id: "r-block", Middlewares: []string{"waf-block"}},
			url:         sqli,
			expect:      http.StatusForbidden,
			explanation: "override that blocks; the global WAF is skipped but the route's own WAF blocks",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := ApplyRouteMiddlewares(backend, tc.route, nil, mwStore, gStore, nil, nil)
			if got := send(h, tc.url); got != tc.expect {
				t.Errorf("got %d, want %d — %s", got, tc.expect, tc.explanation)
			}
		})
	}
}

// TestApplyRouteMiddlewares_GlobalWAFAppliesWhenDisabledOverride confirms the
// fail-safe direction: the whole scheme rests on the global WAF being the
// default, so a route with no WAF middleware must be protected whenever the
// global WAF is enabled — the case an operator relies on by simply toggling
// "protect all routes" and attaching nothing per route.
func TestApplyRouteMiddlewares_GlobalWAFProtectsUnconfiguredRoutes(t *testing.T) {
	gStore := fakeGlobalStore{cfg: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, ParanoiaLevel: 1},
	}}
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := ApplyRouteMiddlewares(backend, &gateonv1.Route{Id: "bare"}, nil, fakeMWStore{}, gStore, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/?id=1%27%20OR%20%271%27%3D%271%20--%20", strings.NewReader(""))
	req.Header.Set("X-Gateon-Test-Reputation", "100")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("bare route with global WAF enabled: got %d, want 403 (global WAF must protect it)", rr.Code)
	}
}
