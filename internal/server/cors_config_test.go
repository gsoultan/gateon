// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func mgmtCORS(c *gateonv1.CorsConfig) *gateonv1.ManagementConfig {
	return &gateonv1.ManagementConfig{Cors: c}
}

// preflight runs an OPTIONS request through the handler and returns the response
// headers, which is the only place CORS settings are observable.
func preflight(t *testing.T, cfg *gateonv1.ManagementConfig, origin string) http.Header {
	t.Helper()
	h := BuildManagementCORS(cfg).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodOptions, "/api", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result().Header
}

// TestConfiguredExposedHeadersAreHonoured is the regression guard: the exposed
// header list was hardcoded to the gRPC-Web set, so cors.exposed_headers did
// nothing at all.
func TestConfiguredExposedHeadersAreHonoured(t *testing.T) {
	got := mergeExposedHeaders([]string{"X-Request-Id", "X-Total-Count"})

	for _, want := range []string{"X-Request-Id", "X-Total-Count"} {
		if !contains(got, want) {
			t.Errorf("exposed headers %v missing configured %q", got, want)
		}
	}
}

// The gRPC-Web headers must survive whatever the operator configures: the
// dashboard's entire API surface needs them, and a config that replaced them
// would look like a UI bug rather than a CORS setting.
func TestGrpcWebHeadersSurviveConfiguration(t *testing.T) {
	for _, configured := range [][]string{nil, {}, {"X-Custom"}} {
		got := mergeExposedHeaders(configured)
		for _, required := range grpcWebExposedHeaders {
			if !contains(got, required) {
				t.Errorf("configured=%v dropped required %q", configured, required)
			}
		}
	}
}

func TestExposedHeadersAreDedupedAndTrimmed(t *testing.T) {
	got := mergeExposedHeaders([]string{"  X-Custom  ", "X-Custom", "", "   ", "grpc-status"})

	if n := count(got, "X-Custom"); n != 1 {
		t.Errorf("X-Custom appears %d times, want 1", n)
	}
	// Header names are case-insensitive, so this must not be sent alongside
	// the canonical "Grpc-Status".
	if n := count(got, "grpc-status"); n != 0 {
		t.Errorf("case-variant duplicate of Grpc-Status was kept: %v", got)
	}
	for _, h := range got {
		if h != strings.TrimSpace(h) || h == "" {
			t.Errorf("untrimmed or empty entry %q in %v", h, got)
		}
	}
}

// MaxAge was never passed, so browsers cached no preflight and every
// cross-origin call paid for one.
func TestMaxAgeReachesThePreflightResponse(t *testing.T) {
	h := preflight(t, mgmtCORS(&gateonv1.CorsConfig{
		AllowedOrigins: []string{"https://app.example.com"},
		MaxAge:         3600,
	}), "https://app.example.com")

	got := h.Get("Access-Control-Max-Age")
	if got == "" {
		t.Fatal("no Access-Control-Max-Age header; the setting is still dropped")
	}
	if n, err := strconv.Atoi(got); err != nil || n != 3600 {
		t.Errorf("Access-Control-Max-Age = %q, want 3600", got)
	}
}

// Unset stays unset: zero means the browser caches nothing, which is the
// behaviour before this change.
func TestMaxAgeUnsetSendsNoHeader(t *testing.T) {
	h := preflight(t, mgmtCORS(&gateonv1.CorsConfig{
		AllowedOrigins: []string{"https://app.example.com"},
	}), "https://app.example.com")

	if got := h.Get("Access-Control-Max-Age"); got != "" {
		t.Errorf("Access-Control-Max-Age = %q, want it absent when unconfigured", got)
	}
}

// A negative value is meaningless to browsers and must not be forwarded.
func TestNegativeMaxAgeIsIgnored(t *testing.T) {
	h := preflight(t, mgmtCORS(&gateonv1.CorsConfig{
		AllowedOrigins: []string{"https://app.example.com"},
		MaxAge:         -5,
	}), "https://app.example.com")

	if got := h.Get("Access-Control-Max-Age"); got != "" {
		t.Errorf("Access-Control-Max-Age = %q, want it absent for a negative setting", got)
	}
}

// A nil config must still produce a working handler for the dashboard.
func TestNilConfigStillExposesGrpcWebHeaders(t *testing.T) {
	got := mergeExposedHeaders(nil)
	if len(got) != len(grpcWebExposedHeaders) {
		t.Fatalf("got %d headers, want the %d required ones", len(got), len(grpcWebExposedHeaders))
	}
}

// actualResponse runs a real (non-preflight) cross-origin request, which is
// where Access-Control-Expose-Headers is emitted.
func actualResponse(t *testing.T, cfg *gateonv1.ManagementConfig, origin string) http.Header {
	t.Helper()
	h := BuildManagementCORS(cfg).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result().Header
}

// This guards the wiring, not the helper. Asserting on mergeExposedHeaders alone
// still passes if the call site goes back to the hardcoded list, which is
// exactly the bug being fixed — the header has to be observed on the wire.
func TestConfiguredExposedHeadersReachTheResponse(t *testing.T) {
	h := actualResponse(t, mgmtCORS(&gateonv1.CorsConfig{
		AllowedOrigins: []string{"https://app.example.com"},
		ExposedHeaders: []string{"X-Request-Id"},
	}), "https://app.example.com")

	got := h.Get("Access-Control-Expose-Headers")
	if !strings.Contains(got, "X-Request-Id") {
		t.Errorf("Access-Control-Expose-Headers = %q, want the configured X-Request-Id", got)
	}
	// And the gRPC-Web headers the dashboard needs must still be there.
	if !strings.Contains(got, "Grpc-Status") {
		t.Errorf("Access-Control-Expose-Headers = %q dropped the required Grpc-Status", got)
	}
}

func contains(hs []string, want string) bool { return count(hs, want) > 0 }

func count(hs []string, want string) int {
	n := 0
	for _, h := range hs {
		if h == want {
			n++
		}
	}
	return n
}
