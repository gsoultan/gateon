// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// sessionCookieFrom runs one of the cookie helpers and returns the cookie it
// set, by parsing the response the way a browser would.
func sessionCookieFrom(t *testing.T, r *http.Request, set func(http.ResponseWriter, *http.Request)) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	set(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("no %s cookie was set; headers: %v", sessionCookieName, rec.Header())
	return nil
}

// TestSessionCookieIsSecureBehindATerminatingProxy is the regression test for
// the management session cookie losing its Secure attribute.
//
// All three call sites passed `r.TLS != nil`, which answers "did this process
// terminate the TLS". Behind a load balancer, ingress or CDN that is nil on a
// request the user made over HTTPS, so the admin session cookie was set without
// Secure in exactly the deployments that terminate TLS elsewhere — and would
// then ride the next plaintext request to the same host.
//
// The bool is gone; the helpers take the request and ask request.IsSecure,
// which honours X-Forwarded-Proto only from a trusted peer.
func TestSessionCookieIsSecureBehindATerminatingProxy(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(*http.Request) *http.Request
		wantSecure bool
	}{
		{
			name: "direct TLS to this process",
			prepare: func(r *http.Request) *http.Request {
				r.TLS = &tls.ConnectionState{}
				return r
			},
			wantSecure: true,
		},
		{
			// r.TLS is nil here — this is the case that was broken. The proto
			// is carried the way RealIP carries it once it has decided the peer
			// is trusted, rather than by setting the raw header: nothing is a
			// trusted proxy until GATEON_TRUSTED_PROXIES says so, so a bare
			// X-Forwarded-Proto from an unknown peer is ignored by design.
			name: "TLS terminated upstream, forwarded by a trusted peer",
			prepare: func(r *http.Request) *http.Request {
				return r.WithContext(request.WithForwardedProto(r.Context(), "https"))
			},
			wantSecure: true,
		},
		{
			name: "plain http, no proxy",
			prepare: func(r *http.Request) *http.Request {
				r.RemoteAddr = "203.0.113.5:9999"
				return r
			},
			wantSecure: false,
		},
		{
			// The header alone must not be enough, or any client could ask for
			// a cookie posture by sending a header.
			name: "X-Forwarded-Proto from an untrusted peer is ignored",
			prepare: func(r *http.Request) *http.Request {
				r.RemoteAddr = "203.0.113.5:9999"
				r.Header.Set("X-Forwarded-Proto", "https")
				return r
			},
			wantSecure: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.prepare(httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil))

			c := sessionCookieFrom(t, req, func(w http.ResponseWriter, r *http.Request) {
				SetSessionCookie(w, r, "session-token-value", 3600)
			})
			if c.Secure != tt.wantSecure {
				t.Errorf("Secure = %v, want %v", c.Secure, tt.wantSecure)
			}

			// Clearing has to make the same decision from the same input: a
			// browser will not clear a Secure cookie with a non-Secure
			// Set-Cookie on an HTTPS origin.
			cleared := sessionCookieFrom(t, req, ClearSessionCookie)
			if cleared.Secure != c.Secure {
				t.Errorf("clear Secure = %v but set Secure = %v; the cookie would not be cleared",
					cleared.Secure, c.Secure)
			}
		})
	}
}

// TestSessionCookieCarriesItsOtherAttributes pins the attributes that make this
// cookie unreadable to script, which is the whole reason the token is not in
// localStorage.
func TestSessionCookieCarriesItsOtherAttributes(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	c := sessionCookieFrom(t, req, func(w http.ResponseWriter, r *http.Request) {
		SetSessionCookie(w, r, "tok", 3600)
	})

	if !c.HttpOnly {
		t.Error("HttpOnly is unset; any stored XSS then reads the admin session")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if c.MaxAge != 3600 {
		t.Errorf("MaxAge = %d, want 3600", c.MaxAge)
	}
	if c.Value != "tok" {
		t.Errorf("Value = %q, want the token", c.Value)
	}
}

// TestClearSessionCookieExpiresIt checks the clear actually expires rather than
// setting an empty cookie that lives for its full lifetime.
func TestClearSessionCookieExpiresIt(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	c := sessionCookieFrom(t, req, ClearSessionCookie)

	if c.Value != "" {
		t.Errorf("Value = %q, want empty", c.Value)
	}
	if c.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want a negative value so the browser deletes it", c.MaxAge)
	}
	if !c.HttpOnly {
		t.Error("HttpOnly is unset on the clearing cookie; the attributes must match")
	}
}

// TestSessionCookieValueIsEscaped covers the switch from hand-built header text
// to http.SetCookie. The token is server-generated today, so this is not a live
// hole — it is a guarantee that stays true if that ever changes.
func TestSessionCookieValueIsEscaped(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, req, "abc; Domain=evil.example.com", 3600)

	// The value is quoted rather than stripped, so a string search for the
	// injected text still finds it -- inside the value, where it is inert. What
	// matters is that it did not become an attribute, so parse it back.
	parsed := rec.Result().Cookies()
	if len(parsed) != 1 {
		t.Fatalf("got %d cookies, want 1: %s", len(parsed), rec.Header().Get("Set-Cookie"))
	}
	if parsed[0].Domain != "" {
		t.Errorf("a token containing cookie syntax set Domain=%q", parsed[0].Domain)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), `"`) {
		t.Errorf("the value was not quoted, so the separator may still be live: %s",
			rec.Header().Get("Set-Cookie"))
	}
}
