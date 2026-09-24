// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const hostileOrigin = "https://evil.example"

// corsGrant sends a cross-origin request with method, which must be one the
// policy allows: rs/cors adds no headers for a method outside its list, so a
// disallowed one would read as "origin refused" whatever the origin rule says.
func corsGrant(t *testing.T, h http.Handler, method string) (allowOrigin, allowCredentials string) {
	t.Helper()
	req := httptest.NewRequest(method, "http://gateway.example/api", nil)
	req.Header.Set("Origin", hostileOrigin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Header().Get("Access-Control-Allow-Origin"), rec.Header().Get("Access-Control-Allow-Credentials")
}

var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

// TestGRPCWebWithNoOriginsGrantsNoCredentials builds grpcweb as the dashboard's
// editor first saves it, with no origins named. It echoed any Origin back with
// Access-Control-Allow-Credentials: true -- the grant a browser honours for a
// credentialed request -- so any website could make cookie-bearing calls
// through the gateway and read the answers.
func TestGRPCWebWithNoOriginsGrantsNoCredentials(t *testing.T) {
	origin, creds := corsGrant(t, GRPCWeb()(noopHandler), http.MethodPost)
	if creds == "true" && origin == hostileOrigin {
		t.Fatalf("an unnamed origin was granted credentialed access: Allow-Origin %q, Allow-Credentials %q", origin, creds)
	}
}

// TestRestrictedCORSPresetGrantsNoOrigin applies the "Restricted" preset the
// way the dashboard saves it: the preset name and an empty origin list. rs/cors
// reads the empty list as every origin, so the locked-down choice answered any
// Origin with Access-Control-Allow-Origin: *.
func TestRestrictedCORSPresetGrantsNoOrigin(t *testing.T) {
	mw, err := NewCORS(map[string]string{
		"preset": "restricted", "allowed_origins": "", "allowed_methods": "GET",
		"allowed_headers": "Accept", "allow_credentials": "false", "max_age": "600",
	})
	if err != nil {
		t.Fatalf("NewCORS: %v", err)
	}
	if origin, _ := corsGrant(t, mw(noopHandler), http.MethodGet); origin != "" {
		t.Fatalf("the restricted preset granted %q cross-origin access (Allow-Origin %q)", hostileOrigin, origin)
	}
}

// TestNamedOriginsStillGranted keeps both fixes from closing what an operator
// opened on purpose.
func TestNamedOriginsStillGranted(t *testing.T) {
	mw, err := NewCORS(map[string]string{"allowed_origins": hostileOrigin, "allow_credentials": "true"})
	if err != nil {
		t.Fatalf("NewCORS: %v", err)
	}
	if origin, creds := corsGrant(t, mw(noopHandler), http.MethodGet); origin != hostileOrigin || creds != "true" {
		t.Fatalf("a named origin with credentials got Allow-Origin %q, Allow-Credentials %q", origin, creds)
	}
}
