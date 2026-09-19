// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The auth service decides on the X-Forwarded-* headers the gateway sets:
// method, URI, host, scheme and client address. They were set *before* the
// client's own headers were copied onto the auth request with Add, so a client
// sending its own X-Forwarded-Uri arrived at the auth service as a second value
// on the same header. Go's Header.Get returns the first, but most other stacks
// join the values ("/admin, /public") or take the last -- and either way the
// auth service is now reasoning about a value the client chose.

// forwardedHeadersSeen runs one request and returns what the auth service saw.
func forwardedHeadersSeen(t *testing.T, cfg ForwardAuthConfig, req *http.Request) http.Header {
	t.Helper()
	var seen http.Header
	cfg.Address = authService(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
	rr, _ := runForwardAuth(t, cfg, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	return seen
}

func TestForwardAuthReplacesClientSuppliedForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/users", nil)
	req.Host = "api.example.com"
	req.RemoteAddr = "203.0.113.9:4444"
	for h, v := range map[string]string{
		"X-Forwarded-Method": "GET",
		"X-Forwarded-Uri":    "/public",
		"X-Forwarded-Host":   "public.example.com",
		"X-Forwarded-Proto":  "https",
		"X-Forwarded-For":    "10.0.0.1",
	} {
		req.Header.Set(h, v)
	}

	seen := forwardedHeadersSeen(t, ForwardAuthConfig{}, req)

	for h, v := range map[string]string{
		"X-Forwarded-Method": "POST",
		"X-Forwarded-Uri":    "/admin/users",
		"X-Forwarded-Host":   "api.example.com",
		"X-Forwarded-Proto":  "http",
		"X-Forwarded-For":    "203.0.113.9",
	} {
		if got := seen.Values(h); len(got) != 1 || got[0] != v {
			t.Errorf("%s: auth service saw %q, want exactly [%q]", h, got, v)
		}
	}
}

func TestForwardAuthForwardsATrustedXFFExactlyOnce(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 198.51.100.7")

	seen := forwardedHeadersSeen(t, ForwardAuthConfig{TrustForwardHeader: true}, req)

	if got := seen.Values("X-Forwarded-For"); len(got) != 1 || got[0] != "10.0.0.1, 198.51.100.7" {
		t.Errorf("X-Forwarded-For: auth service saw %q, want the trusted chain exactly once", got)
	}
}

func TestForwardAuthUnlimitedBodyForwardsTheWholeBody(t *testing.T) {
	var got string
	addr := authService(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader("payload"))

	rr, _ := runForwardAuth(t, ForwardAuthConfig{Address: addr, ForwardBody: true, MaxBodySize: -1}, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rr.Code)
	}
	if got != "payload" {
		t.Errorf("auth service received body %q, want %q: MaxBodySize -1 is documented as unlimited", got, "payload")
	}
}
