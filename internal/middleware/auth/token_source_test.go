// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ExtractToken decides where a credential may come from, and PasetoAuth decides
// what happens when there is nothing to verify it with. Both shipped at 0%
// coverage.
//
// They are worth testing together because each encodes a decision that is
// invisible in the code: one narrows where a token is accepted from, the other
// chooses which way to fail when the verifier is missing. A narrowing that
// quietly stops narrowing, and a failure that quietly goes the other way, are
// the two shapes this package's history is made of.

func reqWith(path string, hdr map[string]string, cookie string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	return r
}

// TestExtractTokenPrefersCookieThenBearer pins the precedence.
func TestExtractTokenPrefersCookieThenBearer(t *testing.T) {
	// Cookie wins over a Bearer header.
	r := reqWith("/", map[string]string{"Authorization": "Bearer header-token"}, "cookie-token")
	if got := ExtractToken(r); got != "cookie-token" {
		t.Errorf("got %q, want the cookie to win", got)
	}

	// Bearer when there is no cookie.
	r = reqWith("/", map[string]string{"Authorization": "Bearer header-token"}, "")
	if got := ExtractToken(r); got != "header-token" {
		t.Errorf("got %q, want the bearer token", got)
	}

	// An empty cookie is not a token, so the header is still consulted.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: ""})
	r.Header.Set("Authorization", "Bearer header-token")
	if got := ExtractToken(r); got != "header-token" {
		t.Errorf("got %q, want the bearer token when the cookie is empty", got)
	}
}

// TestBearerSchemeIsRequired covers the header parsing.
//
// Accepting a bare value, or a different scheme, would let a client present a
// Basic credential where a Bearer token is expected and have it forwarded to a
// verifier that was never asked that question.
func TestBearerSchemeIsRequired(t *testing.T) {
	for _, tc := range []struct{ name, header, want string }{
		{"bearer", "Bearer abc", "abc"},
		{"case insensitive scheme", "bEaReR abc", "abc"},
		{"no scheme", "abc", ""},
		{"basic scheme", "Basic YWxpY2U6cHc=", ""},
		{"empty", "", ""},
		{"scheme only", "Bearer ", ""},
		{"too short to be a scheme", "Bear", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := reqWith("/", map[string]string{"Authorization": tc.header}, "")
			if got := ExtractToken(r); got != tc.want {
				t.Errorf("ExtractToken with %q = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestQueryTokensAreOnlyAcceptedForWebSocketAndSSE is the narrowing.
//
// A token in a query string is written into access logs, browser history and any
// Referer the page later sends. That is why it is not a general-purpose place to
// put a credential, and it is accepted only for the two protocols that cannot
// carry a header: a WebSocket handshake and an EventSource subscription, neither
// of which lets the client set Authorization.
//
// The narrowing is what has to hold. If it stops holding, every ordinary request
// gains a way to pass a credential through a channel that gets logged.
func TestQueryTokensAreOnlyAcceptedForWebSocketAndSSE(t *testing.T) {
	const path = "/stream?token=qs-token"

	t.Run("refused for an ordinary request", func(t *testing.T) {
		if got := ExtractToken(reqWith(path, nil, "")); got != "" {
			t.Errorf("a plain request extracted %q from the query string; tokens there "+
				"end up in access logs, history and Referer headers, which is the "+
				"reason this is restricted", got)
		}
	})

	t.Run("accepted for a websocket handshake", func(t *testing.T) {
		r := reqWith(path, map[string]string{"Upgrade": "websocket"}, "")
		if got := ExtractToken(r); got != "qs-token" {
			t.Errorf("got %q, want the query token; a WebSocket client cannot set "+
				"Authorization, so refusing it here makes the protocol unusable", got)
		}
	})

	t.Run("accepted for an EventSource subscription", func(t *testing.T) {
		r := reqWith(path, map[string]string{"Accept": "text/event-stream"}, "")
		if got := ExtractToken(r); got != "qs-token" {
			t.Errorf("got %q, want the query token for SSE", got)
		}
	})

	t.Run("header matching is case insensitive", func(t *testing.T) {
		// Browsers and proxies do not agree on casing, and a check that only
		// matched one spelling would refuse real clients.
		for _, h := range []map[string]string{
			{"Upgrade": "WebSocket"},
			{"Upgrade": "WEBSOCKET"},
			{"Accept": "TEXT/EVENT-STREAM"},
			{"Accept": "text/html, text/event-stream;q=0.9"},
			{"Content-Type": "text/event-stream"},
		} {
			if got := ExtractToken(reqWith(path, h, "")); got != "qs-token" {
				t.Errorf("with headers %v the query token was refused", h)
			}
		}
	})

	t.Run("all three parameter names", func(t *testing.T) {
		for _, p := range []string{"token", "access_token", "auth"} {
			r := reqWith("/s?"+p+"=v", map[string]string{"Upgrade": "websocket"}, "")
			if got := ExtractToken(r); got != "v" {
				t.Errorf("query parameter %q gave %q, want \"v\"", p, got)
			}
		}
	})
}

// denyingVerifier is a TokenVerifier that rejects everything.
type denyingVerifier struct{}

func (denyingVerifier) VerifyToken(string) (any, error) { return nil, errors.New("nope") }

// acceptingVerifier accepts any token and returns fixed claims.
type acceptingVerifier struct{}

func (acceptingVerifier) VerifyToken(string) (any, error) {
	return map[string]any{"sub": "user-1"}, nil
}

// TestPasetoAuthDeniesWithoutAVerifier pins the decision the code documents.
//
// PasetoAuth tolerates a nil verifier deliberately: it is built once at startup,
// when the verifier may not exist yet, and refusing to construct would force the
// caller to decide at construction time whether authentication will ever be
// possible. The whole point of tolerating it is that the middleware then *denies*
// — a nil verifier that fell through would be an unauthenticated route that looks
// configured, which is exactly the shape of this project's first-run bypass.
func TestPasetoAuthDeniesWithoutAVerifier(t *testing.T) {
	reached := false
	h := PasetoAuth(nil, AuthBaseConfig{})(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	r := reqWith("/", map[string]string{"Authorization": "Bearer anything"}, "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)

	if reached {
		t.Error("a nil verifier let the request through to the backend. The route " +
			"reads as authenticated and is not, which is the failure mode the " +
			"tolerated-nil design exists to avoid.")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

// TestPasetoAuthRequiresAToken covers the no-credential path.
func TestPasetoAuthRequiresAToken(t *testing.T) {
	h := PasetoAuth(acceptingVerifier{}, AuthBaseConfig{})(okHandler())

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reqWith("/", nil, ""))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("a request with no token got %d, want 401 — the verifier accepts "+
			"anything, so reaching it at all would mean an absent credential is "+
			"treated as a valid one", rr.Code)
	}
}

// TestPasetoAuthRejectsAnInvalidToken covers the verifier saying no.
func TestPasetoAuthRejectsAnInvalidToken(t *testing.T) {
	h := PasetoAuth(denyingVerifier{}, AuthBaseConfig{})(okHandler())

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reqWith("/", map[string]string{"Authorization": "Bearer bad"}, ""))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rr.Code)
	}
}

// TestPasetoAuthAcceptsAValidToken is the control.
//
// Without it every assertion above passes on a middleware that refuses
// everything, which is the way an auth test becomes decoration.
func TestPasetoAuthAcceptsAValidToken(t *testing.T) {
	h := PasetoAuth(acceptingVerifier{}, AuthBaseConfig{})(okHandler())

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reqWith("/", map[string]string{"Authorization": "Bearer good"}, ""))
	if rr.Code != http.StatusOK {
		t.Errorf("a valid token got %d, want 200; the tests above would then be "+
			"asserting against a middleware that refuses everything", rr.Code)
	}
}

// TestPasetoAuthAcceptsATokenFromTheSessionCookie covers the browser path.
func TestPasetoAuthAcceptsATokenFromTheSessionCookie(t *testing.T) {
	h := PasetoAuth(acceptingVerifier{}, AuthBaseConfig{})(okHandler())

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, reqWith("/", nil, "session-value"))
	if rr.Code != http.StatusOK {
		t.Errorf("a session cookie got %d, want 200 — the dashboard keeps its token "+
			"only in the HttpOnly cookie, so this is its only way in", rr.Code)
	}
}
