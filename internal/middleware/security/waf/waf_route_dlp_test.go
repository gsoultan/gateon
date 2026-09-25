// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// routeWAFServing builds a route's WAF the way the middleware factory does,
// over an origin that returns a card number.
func routeWAFServing(t *testing.T, cfg map[string]string, global *gateonv1.WafConfig) *httptest.ResponseRecorder {
	t.Helper()
	cfg["route_id"] = t.Name()
	var deps security.Deps
	if global != nil {
		deps.GlobalStore = &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{Waf: global}}
	}
	mw, err := NewWAF(cfg, deps)
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	body := `{"card":"` + leakVisa + `"}`
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write([]byte(body))
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/account", nil)
	req.Header.Set("Accept-Encoding", "identity")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestRouteWAFWithDLPInspectsResponses: a route's own WAF read dlp=true into
// EnableDLP and never turned on the response phase that DLP runs in, so a
// route configured to stop card numbers leaking passed every one. The existing
// DLP tests built WAFConfig by hand with the response phase on, and never went
// through the factory a route uses.
func TestRouteWAFWithDLPInspectsResponses(t *testing.T) {
	rec := routeWAFServing(t, map[string]string{"dlp": "true"}, nil)
	if strings.Contains(rec.Body.String(), leakVisa) {
		t.Fatalf("status %d: a card number passed a route WAF configured with dlp=true", rec.Code)
	}
}

// TestRouteWAFInheritsTheGlobalDLP: a route with its own WAF skips the global
// one, so whatever the global WAF inspects, the route's must inherit -- or
// attaching a WAF to a route switches its response DLP off. The route took the
// global dlp setting only when the global WAF also had use_crs on, and never
// the enterprise tier's DLP default.
func TestRouteWAFInheritsTheGlobalDLP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		global *gateonv1.WafConfig
	}{
		{"global dlp on without CRS", &gateonv1.WafConfig{Enabled: true, Dlp: true}},
		{"enterprise tier", &gateonv1.WafConfig{Enabled: true, Tier: "enterprise"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := routeWAFServing(t, map[string]string{}, tc.global)
			if strings.Contains(rec.Body.String(), leakVisa) {
				t.Fatalf("status %d: a card number passed a route WAF under a global "+
					"WAF that inspects responses", rec.Code)
			}
		})
	}
}

// TestRouteWAFCanStillTurnDLPOff: inheriting is a default, not an override. A
// route that says dlp=false -- a file download service, say -- keeps it off.
func TestRouteWAFCanStillTurnDLPOff(t *testing.T) {
	rec := routeWAFServing(t, map[string]string{"dlp": "false"},
		&gateonv1.WafConfig{Enabled: true, Dlp: true})
	if !strings.Contains(rec.Body.String(), leakVisa) {
		t.Fatalf("status %d: a route that set dlp=false had its response inspected", rec.Code)
	}
}
