// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func tlsEP(addr string, t gateonv1.EntryPoint_Type) *gateonv1.EntryPoint {
	return &gateonv1.EntryPoint{Address: addr, Type: t, Tls: &gateonv1.TlsConfig{Enabled: true}}
}

func plainEP(addr string) *gateonv1.EntryPoint {
	return &gateonv1.EntryPoint{Address: addr, Type: gateonv1.EntryPoint_HTTP}
}

// The target is derived rather than assumed to be 443: TLS is per-entrypoint
// here, so a gateway listening on 8443 must not send everyone to a dead port.
func TestRedirectTargetIsDerivedFromTheEntrypoints(t *testing.T) {
	for _, tc := range []struct {
		name string
		eps  []*gateonv1.EntryPoint
		want string
	}{
		{"no entrypoints", nil, ""},
		{"no TLS anywhere", []*gateonv1.EntryPoint{plainEP(":80")}, ""},
		{"non-standard port", []*gateonv1.EntryPoint{plainEP(":80"), tlsEP(":8443", gateonv1.EntryPoint_HTTP)}, "8443"},
		{"443 preferred over others", []*gateonv1.EntryPoint{tlsEP(":8443", gateonv1.EntryPoint_HTTP), tlsEP(":443", gateonv1.EntryPoint_HTTP)}, "443"},
		{"deterministic when several", []*gateonv1.EntryPoint{tlsEP(":9443", gateonv1.EntryPoint_HTTP), tlsEP(":8443", gateonv1.EntryPoint_HTTP)}, "8443"},
		{"h2 and h3 count", []*gateonv1.EntryPoint{tlsEP(":443", gateonv1.EntryPoint_HTTP3)}, "443"},
		{"TCP entrypoints do not", []*gateonv1.EntryPoint{tlsEP(":9000", gateonv1.EntryPoint_TCP)}, ""},
		{"malformed address ignored", []*gateonv1.EntryPoint{tlsEP("garbage", gateonv1.EntryPoint_HTTP)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := httpsRedirectPort(tc.eps); got != tc.want {
				t.Fatalf("httpsRedirectPort() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Management must never redirect. It is often reached by IP or over a private
// address with no certificate, and an operator who loses the dashboard has lost
// the means to switch the setting back off.
func TestManagementIsNeverRedirected(t *testing.T) {
	if shouldRedirectToHTTPS(plainEP(":8080"), true, true, "443") {
		t.Fatal("the management entrypoint would be redirected, risking lockout")
	}
	if !shouldRedirectToHTTPS(plainEP(":80"), false, true, "443") {
		t.Fatal("a plain non-management entrypoint should redirect")
	}
}

func TestRedirectOnlyWhenThereIsSomewhereToGo(t *testing.T) {
	if shouldRedirectToHTTPS(plainEP(":80"), false, true, "") {
		t.Error("redirected with no TLS entrypoint configured")
	}
	if shouldRedirectToHTTPS(plainEP(":80"), false, false, "443") {
		t.Error("redirected while auto_redirect is off")
	}
	// An entrypoint already serving TLS has nothing to redirect, and doing so
	// would be a loop.
	if shouldRedirectToHTTPS(tlsEP(":443", gateonv1.EntryPoint_HTTP), false, true, "443") {
		t.Error("a TLS entrypoint would redirect to itself")
	}
}

func TestRedirectURLPreservesHostPathAndQuery(t *testing.T) {
	for _, tc := range []struct {
		name, host, target, port, want string
	}{
		{"default port omitted", "example.com", "/a/b?x=1", "443", "https://example.com/a/b?x=1"},
		{"inbound port stripped", "example.com:80", "/", "443", "https://example.com/"},
		{"non-standard port kept", "example.com", "/p", "8443", "https://example.com:8443/p"},
		{"query preserved", "example.com", "/s?q=a%20b&r=2", "443", "https://example.com/s?q=a%20b&r=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			r.Host = tc.host
			if got := redirectTargetURL(r, tc.port); got != tc.want {
				t.Fatalf("redirectTargetURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// Temporary, not permanent: a 301 is cached by browsers and cannot be taken back
// from clients that already saw it, so a mistaken setting would outlive being
// switched off. 307 also preserves the method, which 302 does not.
func TestRedirectIsTemporaryAndPreservesMethod(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/submit", nil)
	r.Host = "example.com"

	httpsRedirect("443").ServeHTTP(rec, r)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d (temporary, method-preserving)", rec.Code, http.StatusTemporaryRedirect)
	}
	if got := rec.Header().Get("Location"); got != "https://example.com/submit" {
		t.Errorf("Location = %q", got)
	}
}
