// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// The OIDC proxy issues four cookies, one of which carries a raw ID token. Two
// defects were shipped in how they were built, and neither is visible from the
// happy path:
//
//  1. SameSite was never set, so the attribute was omitted entirely and the
//     cross-site posture of the session and CSRF-state cookies was whatever the
//     user's browser happened to default to.
//  2. Secure was derived from r.TLS, which is nil whenever Gateon runs behind
//     another TLS terminator — a load balancer, an ingress, a CDN. In precisely
//     those deployments the session cookie went out without Secure and would
//     ride the next plaintext request to the same host.
//
// These tests pin both. Against the pre-fix code the SameSite assertions fail
// with SameSiteDefaultMode and the forwarded-proto case fails with Secure=false.

// setCookies returns the Set-Cookie headers produced by fn for r.
func setCookies(fn func(http.ResponseWriter, *http.Request), r *http.Request) []*http.Cookie {
	rec := httptest.NewRecorder()
	fn(rec, r)
	return rec.Result().Cookies()
}

// reqWithSecure returns a request whose resolved scheme is https when secure.
func reqWithSecure(secure bool) *http.Request {
	proto := "http"
	if secure {
		proto = "https"
	}
	r := httptest.NewRequest(http.MethodGet, "/app", nil)
	return r.WithContext(request.WithForwardedProto(r.Context(), proto))
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q not set; got %d cookies", name, len(cookies))
	return nil
}

// TestExpireOIDCCookieMirrorsAttributes covers the cleanup path: a Secure cookie
// cannot be cleared by a non-Secure Set-Cookie on an HTTPS origin, so a bare
// deletion would leave the state cookie alive for its full 300s TTL.
func TestExpireOIDCCookieMirrorsAttributes(t *testing.T) {
	for _, secure := range []bool{true, false} {
		rec := httptest.NewRecorder()
		expireOIDCCookie(rec, reqWithSecure(secure), "gateon_state_r1")

		c := findCookie(t, rec.Result().Cookies(), "gateon_state_r1")
		if c.MaxAge >= 0 {
			t.Errorf("MaxAge = %d, want negative so the browser drops it", c.MaxAge)
		}
		if !c.HttpOnly {
			t.Error("HttpOnly = false, want true to match how it was set")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want SameSiteLaxMode", c.SameSite)
		}
		if c.Secure != secure {
			t.Errorf("Secure = %v, want %v to match how it was set", c.Secure, secure)
		}
	}
}

// TestIsSecureBehindTLSTerminatingProxy is the root cause: r.TLS answers "did I
// terminate the TLS", not "did the user use HTTPS". Only the second question
// determines whether the cookie may omit Secure.
func TestIsSecureBehindTLSTerminatingProxy(t *testing.T) {
	tests := []struct {
		name string
		req  func() *http.Request
		want bool
	}{
		{
			name: "plain http, no proxy",
			req:  func() *http.Request { return httptest.NewRequest(http.MethodGet, "/app", nil) },
			want: false,
		},
		{
			name: "https terminated upstream, forwarded proto honored",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/app", nil)
				// r.TLS stays nil, exactly as it is behind a load balancer.
				return r.WithContext(request.WithForwardedProto(r.Context(), "https"))
			},
			want: true,
		},
		{
			name: "forwarded proto says http",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/app", nil)
				return r.WithContext(request.WithForwardedProto(r.Context(), "http"))
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := request.IsSecure(tt.req()); got != tt.want {
				t.Errorf("request.IsSecure() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewOIDCCookieAttributes exercises the single construction point every
// cookie in this middleware goes through, so weakening any attribute there
// fails here rather than in a browser.
func TestNewOIDCCookieAttributes(t *testing.T) {
	tests := []struct {
		name       string
		forwarded  string // X-Forwarded-Proto as resolved by request.Scheme
		wantSecure bool
	}{
		{name: "behind an HTTPS-terminating proxy", forwarded: "https", wantSecure: true},
		{name: "plain http", forwarded: "http", wantSecure: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := httptest.NewRequest(http.MethodGet, "/app", nil)
			// r.TLS stays nil in both cases — that is the whole point.
			r := base.WithContext(request.WithForwardedProto(base.Context(), tt.forwarded))

			c := newOIDCCookie(r, "gateon_session_r1", "id-token", 300)

			if c.Secure != tt.wantSecure {
				t.Errorf("Secure = %v, want %v; r.TLS is nil here, so deriving Secure "+
					"from it would send the session cookie without Secure over HTTPS",
					c.Secure, tt.wantSecure)
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want SameSiteLaxMode; unset omits the "+
					"attribute and lets the browser pick the posture", c.SameSite)
			}
			if !c.HttpOnly {
				t.Error("HttpOnly = false; the ID token would be readable from script")
			}
			if c.Path != "/" {
				t.Errorf("Path = %q, want \"/\"", c.Path)
			}
		})
	}
}

// TestOIDCSessionCookieGoesOutOnTheWire is the end-to-end shape check: the
// attributes must survive serialization into the Set-Cookie header, not just
// exist on the struct.
func TestOIDCSessionCookieGoesOutOnTheWire(t *testing.T) {
	base := httptest.NewRequest(http.MethodGet, "/app", nil)
	r := base.WithContext(request.WithForwardedProto(base.Context(), "https"))

	cookies := setCookies(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, newOIDCCookie(r, "gateon_session_r1", "id-token", 300))
	}, r)

	c := findCookie(t, cookies, "gateon_session_r1")
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("serialized cookie lost attributes: Secure=%v HttpOnly=%v SameSite=%v",
			c.Secure, c.HttpOnly, c.SameSite)
	}
}
