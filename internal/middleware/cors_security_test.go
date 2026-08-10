// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// These tests pin the one CORS invariant a gateway must never break:
// a response may reflect an arbitrary Origin, or it may allow credentials,
// but never both. The combination lets any website on the internet issue
// credentialed cross-origin requests to every backend behind the gateway and
// read the responses — session-riding with no user interaction.
//
// Browsers already refuse `Access-Control-Allow-Origin: *` together with
// credentials, which is exactly why reflecting the caller's Origin instead of
// sending `*` is dangerous: it looks like a narrow allowlist to the browser and
// is honoured, while behaving like a wildcard in practice.
//
// Found by scanning a live gateway with nikto, which reported its own
// `Origin: nikto.example.com` echoed back in Access-Control-Allow-Origin.

const evilOrigin = "https://attacker.example.com"

// assertNotCredentialedWildcard fails when a response reflects the caller's
// origin and allows credentials at the same time.
func assertNotCredentialedWildcard(t *testing.T, res *http.Response, label string) {
	t.Helper()
	allowOrigin := res.Header.Get("Access-Control-Allow-Origin")
	allowCreds := res.Header.Get("Access-Control-Allow-Credentials")

	if allowOrigin == evilOrigin && allowCreds == "true" {
		t.Errorf("%s: reflected attacker origin %q with Access-Control-Allow-Credentials: true.\n"+
			"Any site can now read credentialed responses from every backend behind this gateway.\n"+
			"Fix: drop credentials for unlisted origins, or reflect only a configured allowlist.",
			label, allowOrigin)
	}
}

func TestGlobalCORS_DoesNotReflectArbitraryOriginWithCredentials(t *testing.T) {
	handler := GlobalCORS()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("simple request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/account", nil)
		req.Header.Set("Origin", evilOrigin)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assertNotCredentialedWildcard(t, rr.Result(), "GlobalCORS simple request")
	})

	t.Run("preflight", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/account", nil)
		req.Header.Set("Origin", evilOrigin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assertNotCredentialedWildcard(t, rr.Result(), "GlobalCORS preflight")
	})
}

func TestBypassCORS_DoesNotReflectArbitraryOriginWithCredentials(t *testing.T) {
	handler := BypassCORS()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/account", nil)
	req.Header.Set("Origin", evilOrigin)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assertNotCredentialedWildcard(t, rr.Result(), "BypassCORS simple request")
}

// A permissive gateway default may still expose Authorization to any origin,
// but only when credentials are off. Exposing it *and* allowing credentials
// hands the caller's bearer token to any page that asks.
func TestGlobalCORS_DoesNotExposeAuthorizationToArbitraryOriginWithCredentials(t *testing.T) {
	handler := GlobalCORS()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/account", nil)
	req.Header.Set("Origin", evilOrigin)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	res := rr.Result()

	if res.Header.Get("Access-Control-Allow-Credentials") != "true" {
		return // credentials off: exposing headers is not a token-disclosure risk
	}
	for _, exposed := range res.Header.Values("Access-Control-Expose-Headers") {
		if containsFold(exposed, "authorization") {
			t.Errorf("Authorization is exposed to arbitrary origin %q with credentials allowed: %q",
				evilOrigin, exposed)
		}
	}
}

func containsFold(haystack, needle string) bool {
	h, n := []rune(haystack), []rune(needle)
	if len(n) == 0 || len(h) < len(n) {
		return len(n) == 0
	}
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
