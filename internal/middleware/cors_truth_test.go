// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// CORS as the dashboard labels it (ADR 0046). The Permissive, Standard and
// gRPC-Web presets sent Access-Control-Allow-Origin: * with
// Access-Control-Allow-Credentials: true, which browsers refuse, so "Allow
// Credentials" did nothing; and an empty Allowed Origins with no preset let
// every origin in, while the same empty field under "Restricted" let none.

// corsAnswer sends a GET from origin through a middleware of type typ built by
// the factory from cfg, and returns the response's CORS headers.
func corsAnswer(t *testing.T, typ string, cfg map[string]string, origin string) (allowOrigin, allowCredentials string) {
	t.Helper()
	mw, err := NewFactory(nil, nil, nil, nil, t.TempDir()).
		Create(&gateonv1.Middleware{Id: "cors-under-test", Type: typ, Config: cfg}, "route-under-test")
	if err != nil {
		t.Fatalf("build %s %v: %v", typ, cfg, err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/grpc-web")
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(rec, req)
	return rec.Header().Get("Access-Control-Allow-Origin"), rec.Header().Get("Access-Control-Allow-Credentials")
}

// TestCORSNeverPairsAWildcardOriginWithCredentials covers every preset that
// grants "*", for both middlewares that take a preset, and a stored config
// that asks for the pair outright.
func TestCORSNeverPairsAWildcardOriginWithCredentials(t *testing.T) {
	cases := []struct {
		typ string
		cfg map[string]string
	}{
		{"cors", map[string]string{"preset": "permissive"}},
		{"cors", map[string]string{"preset": "standard"}},
		{"cors", map[string]string{"preset": "grpc-web"}},
		{"grpcweb", map[string]string{"preset": "grpc-web"}},
		{"cors", map[string]string{"allowed_origins": "*", "allow_credentials": "true"}},
		{"grpcweb", map[string]string{"allowed_origins": "*", "allow_credentials": "true"}},
	}
	for _, tc := range cases {
		origin, creds := corsAnswer(t, tc.typ, tc.cfg, "https://app.example")
		if origin == "" {
			t.Errorf("%s %v: no Access-Control-Allow-Origin; the preset grants every origin", tc.typ, tc.cfg)
		}
		if origin == "*" && creds == "true" {
			t.Errorf("%s %v: Access-Control-Allow-Origin: * with Allow-Credentials: true, a pair browsers refuse",
				tc.typ, tc.cfg)
		}
	}
}

// TestCORSNamedOriginsStillCarryCredentials keeps the fix to the wildcard: a
// named origin with credentials on is reflected and credentialed.
func TestCORSNamedOriginsStillCarryCredentials(t *testing.T) {
	origin, creds := corsAnswer(t, "cors",
		map[string]string{"allowed_origins": "https://app.example", "allow_credentials": "true"}, "https://app.example")
	if origin != "https://app.example" || creds != "true" {
		t.Fatalf("named origin with credentials: ACAO %q ACAC %q, want the origin and true", origin, creds)
	}
}

// TestCORSEmptyOriginListGrantsNoOrigin leaves Allowed Origins empty with no
// preset -- key absent, and blank as the dashboard writes it.
func TestCORSEmptyOriginListGrantsNoOrigin(t *testing.T) {
	for _, cfg := range []map[string]string{{}, {"allowed_origins": ""}, {"allowed_origins": " , "}} {
		if origin, _ := corsAnswer(t, "cors", cfg, "https://evil.example"); origin != "" {
			t.Errorf("cors %v: an empty origin list answered Access-Control-Allow-Origin %q; empty must mean none", cfg, origin)
		}
	}
}

// TestGRPCWebRestrictedPresetGrantsNoOrigin: "Restricted" means no origin on
// the grpcweb middleware too. Its empty list fell into the any-origin default.
func TestGRPCWebRestrictedPresetGrantsNoOrigin(t *testing.T) {
	if origin, _ := corsAnswer(t, "grpcweb", map[string]string{"preset": "restricted"}, "https://evil.example"); origin != "" {
		t.Fatalf("grpcweb restricted answered Access-Control-Allow-Origin %q, want none", origin)
	}
}

// TestCORSPresetWithABlankOriginFieldKeepsThePresetOrigins: the dashboard
// writes a blank allowed_origins next to a preset; the preset's list applies.
func TestCORSPresetWithABlankOriginFieldKeepsThePresetOrigins(t *testing.T) {
	origin, _ := corsAnswer(t, "cors", map[string]string{"preset": "permissive", "allowed_origins": ""}, "https://app.example")
	if origin == "" {
		t.Fatal("permissive preset with a blank origin field granted no origin")
	}
}

// TestCORSWildcardWithCredentialsIsRefusedAtSave saves the pair browsers
// refuse; the save says so instead of storing a switch that does nothing.
func TestCORSWildcardWithCredentialsIsRefusedAtSave(t *testing.T) {
	f := NewFactory(nil, nil, nil, nil, t.TempDir())
	for _, typ := range []string{"cors", "grpcweb"} {
		for _, cfg := range []map[string]string{
			{"allowed_origins": "*", "allow_credentials": "true"},
			{"allowed_origins": "https://a.example, *", "allow_credentials": "true"},
			{"preset": "permissive", "allow_credentials": "true"},
		} {
			if err := f.Validate(&gateonv1.Middleware{Id: "c", Type: typ, Config: cfg}); err == nil {
				t.Errorf("%s %v saved: credentials with origin \"*\" do nothing in a browser", typ, cfg)
			}
		}
		ok := map[string]string{"allowed_origins": "https://a.example", "allow_credentials": "true"}
		if err := f.Validate(&gateonv1.Middleware{Id: "c", Type: typ, Config: ok}); err != nil {
			t.Errorf("%s with a named origin and credentials refused: %v", typ, err)
		}
	}
}
