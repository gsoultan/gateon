// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	wafmw "github.com/gsoultan/gateon/internal/middleware/security/waf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type fixedGlobalStore struct{ cfg *gateonv1.GlobalConfig }

func (s fixedGlobalStore) Get(context.Context) *gateonv1.GlobalConfig { return s.cfg }
func (fixedGlobalStore) GetCertificate(string) (*gateonv1.Certificate, bool) {
	return nil, false
}
func (fixedGlobalStore) Update(context.Context, *gateonv1.GlobalConfig) error { return nil }
func (fixedGlobalStore) ConfigFileExists() bool                               { return true }

type listedMiddlewares []*gateonv1.Middleware

func (l listedMiddlewares) List(context.Context) []*gateonv1.Middleware { return l }
func (l listedMiddlewares) ListPaginated(context.Context, int32, int32, string) ([]*gateonv1.Middleware, int32) {
	return l, int32(len(l))
}
func (listedMiddlewares) All(context.Context) map[string]*gateonv1.Middleware { return nil }
func (listedMiddlewares) Get(context.Context, string) (*gateonv1.Middleware, bool) {
	return nil, false
}
func (listedMiddlewares) Update(context.Context, *gateonv1.Middleware) error { return nil }
func (listedMiddlewares) Delete(context.Context, string) error               { return nil }

func getEffectiveWAF(t *testing.T, svc *api.ApiService) effectiveWAFView {
	t.Helper()
	mux := http.NewServeMux()
	registerWafRuleHandlers(mux, svc)
	req := httptest.NewRequest(http.MethodGet, "/v1/waf/effective", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "v-1", Username: "viewer", Role: auth.RoleViewer}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/waf/effective: %d %s", rr.Code, rr.Body.String())
	}
	var view effectiveWAFView
	if err := json.Unmarshal(rr.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return view
}

// TestEffectiveWAFReportsWhatRuns is the API half of truth T8 and T12. The
// global card read the stored switches, which the global WAF ignores: with the
// dashboard's own "Protect all routes" object every category and malware
// detection read OFF while all of them were enforced, and an audit-only WAF
// was reported the same as an enforcing one. This endpoint answers from the
// engine's config, and a route WAF's answer includes what it inherits.
func TestEffectiveWAFReportsWhatRuns(t *testing.T) {
	// The tier is named: unset, it comes from the process-wide profile, which
	// another test in this package leaves at "minimal" -- a tier that does
	// switch LFI, RCE and malware off, so the answer would depend on test order.
	waf := &gateonv1.WafConfig{Enabled: true, ParanoiaLevel: 1, AuditOnly: true, Tier: "standard"}
	svc := &api.ApiService{
		Globals: fixedGlobalStore{&gateonv1.GlobalConfig{Waf: waf}},
		Middlewares: listedMiddlewares{
			{Id: "w-default", Name: "default", Type: "waf", Config: map[string]string{}},
			{Id: "w-enforce", Name: "enforce", Type: "waf", Config: map[string]string{"audit_only": "false", "sqli": "false"}},
			{Id: "rl", Name: "rl", Type: "ratelimit"},
		},
	}
	view := getEffectiveWAF(t, svc)

	if view.Global.Mode != wafmw.ModeAuditOnly {
		t.Errorf("global mode = %q, want %q (an audit-only WAF blocks nothing)", view.Global.Mode, wafmw.ModeAuditOnly)
	}
	for _, k := range []string{"sqli", "xss", "lfi", "rce", "php", "scanner", "malware_detection", "ransomware_detection"} {
		if !view.Global.Categories[k] {
			t.Errorf("global %s reported off; the global WAF runs it", k)
		}
	}
	if len(view.RouteWAFs) != 2 {
		t.Fatalf("route WAFs = %+v, want the two waf middlewares only", view.RouteWAFs)
	}
	byID := map[string]wafmw.Effective{}
	for _, r := range view.RouteWAFs {
		byID[r.ID] = r.Effective
	}
	if e := byID["w-default"]; e.Mode != wafmw.ModeAuditOnly || !e.Categories["malware_detection"] {
		t.Errorf("default route WAF = %+v, want it to inherit audit-only and malware detection", e)
	}
	if e := byID["w-enforce"]; e.Mode != wafmw.ModeEnforcing || e.Categories["sqli"] || !e.Categories["xss"] {
		t.Errorf("explicit route WAF = %+v, want enforcing, sqli off, xss on", e)
	}

	waf.Enabled = false
	if got := getEffectiveWAF(t, svc).Global.Mode; got != wafmw.ModeOff {
		t.Errorf("global WAF switched off reports mode %q, want %q", got, wafmw.ModeOff)
	}
}
