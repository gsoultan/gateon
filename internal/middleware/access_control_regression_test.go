// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Regression tests for the access-control and request-validation middlewares,
// each pinned to a defect that shipped: a check that could be skipped with a
// client-chosen header, a header computed and never sent, a claim set that
// never reached the policy engine, and a schema that failed to compile into a
// middleware that validated nothing.

func writtenOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})
}

func buildRouteMiddleware(t *testing.T, typ string, cfg map[string]string) Middleware {
	t.Helper()
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	mw, err := f.Create(&gateonv1.Middleware{Type: typ, Config: cfg}, "route-1")
	if err != nil {
		t.Fatalf("build %s: %v", typ, err)
	}
	return mw
}

func TestMaxBodySizeIsNotBypassedByAnUpgradeHeader(t *testing.T) {
	h := traffic.MaxBodySize(8)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(strings.Repeat("x", 64)))
	req.Header.Set("Upgrade", "h2c")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a 64-byte body with an Upgrade header passed an 8-byte limit: got %d, want 413", rr.Code)
	}

	ws := httptest.NewRequest(http.MethodGet, "/ws", nil)
	ws.Header.Set("Connection", "Upgrade")
	ws.Header.Set("Upgrade", "websocket")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, ws)
	if rr.Code != http.StatusOK {
		t.Errorf("websocket handshake got %d, want 200", rr.Code)
	}
}

func TestHeadersMiddlewareEmitsHSTSOnAWrittenResponse(t *testing.T) {
	mw := buildRouteMiddleware(t, "headers", map[string]string{
		"sts_seconds":            "31536000",
		"sts_include_subdomains": "true",
		"force_sts_header":       "true",
	})
	rr := httptest.NewRecorder()
	mw(writtenOK()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	const want = "max-age=31536000; includeSubDomains"
	if got := rr.Result().Header.Get("Strict-Transport-Security"); got != want {
		t.Errorf("Strict-Transport-Security on the wire = %q, want %q", got, want)
	}
}

func TestPolicySeesJWTClaims(t *testing.T) {
	mw, err := security.Policy(security.PolicyConfig{Rules: []security.PolicyRule{{Expression: `auth.sub == "alice"`, Message: "not alice"}}})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(InjectContext(req.Context(), jwt.MapClaims{"sub": "alice"}))
	rr := httptest.NewRecorder()
	mw(writtenOK()).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("policy over the JWT middleware's claims got %d (%s), want 200", rr.Code, strings.TrimSpace(rr.Body.String()))
	}
}

func TestSchemaValidationRejectsAnUncompilableSchemaAtConfigTime(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	_, err := f.Create(&gateonv1.Middleware{Type: "schema_validation", Config: map[string]string{"schema": "{not json"}}, "route-1")
	if err == nil {
		t.Fatal("an uncompilable schema built a middleware that validates nothing")
	}
}

func BenchmarkCORSActualRequest(b *testing.B) {
	h := transform.CORS(transform.CORSConfig{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	})(writtenOK())
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Origin", "https://app.example.com")
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}
