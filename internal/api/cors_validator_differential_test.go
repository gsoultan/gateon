// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const (
	corsProbeURL     = "http://gateon/api/test"
	corsProbeRule    = "Path(`/api/test`)"
	corsProbeRouteID = "rt1"
	corsProbeMWID    = "cors-1"
)

// corsProbe is one request put to both the Diagnostics validator and the real
// middleware built from the same config.
type corsProbe struct {
	name    string
	config  map[string]string
	origin  string
	method  string
	headers map[string]string
}

// corsDifferentialProbes covers every way the hand-rolled validator was known
// to disagree with what the proxy enforces, plus two controls that must stay
// denied on both sides.
//
// Access-Control-Request-Headers values are lowercase because that is what a
// browser sends: the Fetch standard guarantees it, and rs/cors relies on the
// guarantee by matching the list case-sensitively against a lowercased
// allowlist.
func corsDifferentialProbes() []corsProbe {
	preflight := map[string]string{corsRequestMethod: http.MethodPost}
	withHeaders := func(h string) map[string]string {
		m := maps.Clone(preflight)
		m[corsRequestHeaders] = h
		return m
	}
	return []corsProbe{
		{"preset supplies the origins", map[string]string{"preset": "standard"},
			"https://app.example.com", http.MethodGet, nil},
		{"empty origin list means every origin", map[string]string{"allowed_methods": "GET,POST"},
			"https://anything.example", http.MethodGet, nil},
		{"origin matching is case-insensitive", map[string]string{"allowed_origins": "https://Example.com"},
			"https://example.com", http.MethodGet, nil},
		{"authorization is not a default allowed header", corsPreflightConfig(),
			"https://example.com", http.MethodOptions, withHeaders("authorization")},
		{"x-requested-with is a default allowed header", corsPreflightConfig(),
			"https://example.com", http.MethodOptions, withHeaders("x-requested-with")},
		{"permissive preset allows any request header", map[string]string{"preset": "permissive"},
			"https://app.example.com", http.MethodOptions, withHeaders("x-custom-thing")},
		{"wildcard origin pattern", map[string]string{"allowed_origins": "https://*.example.com"},
			"https://app.example.com", http.MethodGet, nil},
		{"credentials with wildcard origin still answer", map[string]string{"allowed_origins": "*", "allow_credentials": "true"},
			"https://app.example.com", http.MethodGet, nil},
		{"an origin outside the allowlist stays denied", map[string]string{"allowed_origins": "https://example.com"},
			"https://evil.example", http.MethodGet, nil},
		{"a method outside the allowlist stays denied", map[string]string{"allowed_origins": "https://example.com", "allowed_methods": "GET"},
			"https://example.com", http.MethodOptions, preflight},
	}
}

func corsPreflightConfig() map[string]string {
	return map[string]string{"allowed_origins": "https://example.com", "allowed_methods": "GET,POST,OPTIONS"}
}

// proxyAllowsCORS reports the verdict a browser would read off the real
// middleware: a response carrying no Access-Control-Allow-Origin is a blocked
// cross-origin request, for both preflights and actual requests.
func proxyAllowsCORS(t *testing.T, p corsProbe) bool {
	t.Helper()
	factory := middleware.NewFactory(nil, nil, nil, nil, t.TempDir())
	mw, err := factory.Create(&gateonv1.Middleware{
		Id: corsProbeMWID, Name: "cors", Type: "cors", Config: maps.Clone(p.config),
	}, corsProbeRouteID)
	if err != nil {
		t.Fatalf("factory could not build the cors middleware: %v", err)
	}

	r := httptest.NewRequest(p.method, corsProbeURL, nil)
	r.Header.Set(corsRequestOrigin, p.origin)
	for k, v := range p.headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, r)
	return rec.Header().Get(corsAllowOrigin) != ""
}

func validateCORSProbe(t *testing.T, p corsProbe) *gateonv1.ValidateCORSResponse {
	t.Helper()
	mw := &gateonv1.Middleware{Id: corsProbeMWID, Name: "cors", Type: "cors", Config: maps.Clone(p.config)}
	rt := &gateonv1.Route{
		Id: corsProbeRouteID, Name: "api", Rule: corsProbeRule, Middlewares: []string{corsProbeMWID},
	}
	svc := &ApiService{
		Routes:      &mockRouteStore{routes: []*gateonv1.Route{rt}},
		Middlewares: &mockMiddlewareStore{middlewares: map[string]*gateonv1.Middleware{corsProbeMWID: mw}},
	}

	resp, err := svc.ValidateCORS(context.Background(), &gateonv1.ValidateCORSRequest{
		Url: corsProbeURL, Origin: p.origin, Method: p.method, Headers: maps.Clone(p.headers),
	})
	if err != nil {
		t.Fatalf("ValidateCORS returned an error: %v", err)
	}
	if resp == nil {
		t.Fatal("ValidateCORS returned no response")
	}
	return resp
}

// TestValidateCORSMatchesProxyEnforcement is the differential test: the
// Diagnostics verdict must equal what the middleware built from the same
// config actually does. The validator used to re-derive CORS policy from the
// raw config by hand, so it disagreed with rs/cors on presets, empty origin
// lists, origin case, default allowed headers and wildcard patterns -- and in
// the Authorization case it told operators a preflight was fine that the proxy
// rejects.
func TestValidateCORSMatchesProxyEnforcement(t *testing.T) {
	for _, p := range corsDifferentialProbes() {
		t.Run(p.name, func(t *testing.T) {
			want := proxyAllowsCORS(t, p)
			got := validateCORSProbe(t, p)
			if got.IsAllowed != want {
				t.Fatalf("validator IsAllowed=%v, proxy allows=%v\n  config:  %v\n  origin:  %q\n  method:  %q\n  headers: %v\n  message: %s",
					got.IsAllowed, want, p.config, p.origin, p.method, p.headers, got.Message)
			}
		})
	}
}

// TestValidateCORSWarnsOnCredentialsWithWildcardOrigin pins the product
// decision: rs/cors answers `Access-Control-Allow-Origin: *` even when
// credentials are configured, so the verdict has to say "allowed" to describe
// the gateway honestly. The browser will still refuse the credentialed use, so
// the warning moves to Suggestions rather than disappearing.
func TestValidateCORSWarnsOnCredentialsWithWildcardOrigin(t *testing.T) {
	p := corsProbe{
		config: map[string]string{"allowed_origins": "*", "allow_credentials": "true"},
		origin: "https://app.example.com",
		method: http.MethodGet,
	}

	resp := validateCORSProbe(t, p)
	if !resp.IsAllowed {
		t.Fatalf("proxy emits Access-Control-Allow-Origin: * here, so the verdict must be allowed: %s", resp.Message)
	}
	if resp.ResponseHeaders[corsAllowOrigin] != "*" {
		t.Fatalf("expected the wildcard origin the proxy sends, got %q", resp.ResponseHeaders[corsAllowOrigin])
	}

	var warned bool
	for _, s := range resp.Suggestions {
		if strings.Contains(strings.ToLower(s), "credential") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("operator must still be warned that browsers reject credentials with '*': %v", resp.Suggestions)
	}
}
