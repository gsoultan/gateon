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

// ForwardAuth delegates the auth decision to an external service and shipped
// with no tests. It is the most trust-laden middleware in the package: the
// backend behind it is told to believe the headers it produces.

// authService spins up a stand-in auth service.
func authService(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// runForwardAuth drives one request and reports what the backend saw.
func runForwardAuth(t *testing.T, cfg ForwardAuthConfig, req *http.Request) (*httptest.ResponseRecorder, http.Header) {
	t.Helper()
	mw, err := ForwardAuth(cfg)
	if err != nil {
		t.Fatalf("build ForwardAuth: %v", err)
	}

	var seen http.Header
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr, seen
}

// TestForwardAuthRequiresAnAbsoluteAddress covers construction.
func TestForwardAuthRequiresAnAbsoluteAddress(t *testing.T) {
	for _, addr := range []string{"", "/verify", "auth.example.com/verify", "://bad"} {
		if _, err := ForwardAuth(ForwardAuthConfig{Address: addr}); err == nil {
			t.Errorf("address %q built without error; a relative address would send "+
				"the auth check nowhere", addr)
		}
	}
}

// TestForwardAuthHonoursTheDecision is the core contract.
func TestForwardAuthHonoursTheDecision(t *testing.T) {
	t.Run("2xx forwards to the backend", func(t *testing.T) {
		addr := authService(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		rr, _ := runForwardAuth(t, ForwardAuthConfig{Address: addr},
			httptest.NewRequest(http.MethodGet, "/resource", nil))
		if rr.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rr.Code)
		}
	})

	t.Run("401 is relayed and the backend is never reached", func(t *testing.T) {
		addr := authService(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="x"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "denied")
		})
		rr, seen := runForwardAuth(t, ForwardAuthConfig{Address: addr},
			httptest.NewRequest(http.MethodGet, "/resource", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", rr.Code)
		}
		if seen != nil {
			t.Error("the backend was reached despite the auth service denying the request")
		}
		if rr.Header().Get("WWW-Authenticate") == "" {
			t.Error("the challenge header was not relayed, so a client cannot tell how " +
				"to authenticate")
		}
	})

	t.Run("an unreachable auth service denies", func(t *testing.T) {
		// A closed port: the decision cannot be made, so it must not default to yes.
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		addr := srv.URL
		srv.Close()

		rr, seen := runForwardAuth(t, ForwardAuthConfig{Address: addr},
			httptest.NewRequest(http.MethodGet, "/resource", nil))
		if rr.Code != http.StatusBadGateway {
			t.Errorf("got %d, want 502", rr.Code)
		}
		if seen != nil {
			t.Error("the backend was reached with the auth service down; an auth " +
				"check that could not run is not an auth check that passed")
		}
	})

	t.Run("a redirect is not a success", func(t *testing.T) {
		// An auth service that 302s to a login page must deny, not follow the
		// redirect and read the login page's 200 as approval.
		addr := authService(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, httptest.NewRequest(http.MethodGet, "/", nil), "/login", http.StatusFound)
		})
		rr, seen := runForwardAuth(t, ForwardAuthConfig{Address: addr},
			httptest.NewRequest(http.MethodGet, "/resource", nil))
		if seen != nil {
			t.Errorf("a 302 from the auth service reached the backend (status %d); "+
				"following it would turn a login page's 200 into an approval", rr.Code)
		}
	})
}

// TestForwardAuthDoesNotLetAClientForgeIdentityHeaders pins the middleware's
// most important guarantee.
//
// auth_response_headers names the headers the auth service produces and the
// backend is told to trust -- X-Auth-User, X-Auth-Roles and so on. The backend
// believes them precisely because the gateway is supposed to guarantee they came
// from the auth service and not from whoever sent the request.
//
// ForwardAuth already clears them from the inbound request before doing anything
// else, which is the right design and is not what this test found; it had simply
// never been exercised. It is worth pinning because the guarantee is invisible:
// the copy at the end only ever *overwrites*, so if the strip were ever removed
// or moved, an auth service that returned 200 without setting an identity header
// -- entirely normal on an anonymous-allowed route -- would leave the client's
// own value in place, and it would arrive at the backend wearing the gateway's
// guarantee. Nothing about that failure is visible from either end.
func TestForwardAuthDoesNotLetAClientForgeIdentityHeaders(t *testing.T) {
	// A permissive auth service: it approves the request but attributes no
	// identity to it.
	addr := authService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cfg := ForwardAuthConfig{
		Address:             addr,
		AuthResponseHeaders: []string{"X-Auth-User", "X-Auth-Roles"},
	}

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X-Auth-User", "admin")
	req.Header.Set("X-Auth-Roles", "superuser")

	rr, seen := runForwardAuth(t, cfg, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("setup: the auth service approved but got %d", rr.Code)
	}

	for _, h := range []string{"X-Auth-User", "X-Auth-Roles"} {
		if got := seen.Get(h); got != "" {
			t.Errorf("the backend received %s: %q straight from the client.\n"+
				"That header is on auth_response_headers, which is the operator "+
				"declaring it comes from the auth service and may be trusted. The "+
				"auth service returned 200 and set no identity — normal for an "+
				"anonymous-allowed route — so nothing overwrote the client's value "+
				"and it arrived at the backend carrying the gateway's guarantee. "+
				"Headers on that list must be cleared from the inbound request, not "+
				"merely overwritten when present.", h, got)
		}
	}
}

// TestForwardAuthCopiesIdentityFromTheAuthService is the positive half.
//
// The clearing above must not break the feature it protects.
func TestForwardAuthCopiesIdentityFromTheAuthService(t *testing.T) {
	addr := authService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Auth-User", "alice")
		w.Header().Set("X-Auth-Roles", "viewer")
		w.Header().Set("X-Not-Listed", "ignored")
		w.WriteHeader(http.StatusOK)
	})

	cfg := ForwardAuthConfig{
		Address:             addr,
		AuthResponseHeaders: []string{"X-Auth-User", "X-Auth-Roles"},
	}

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X-Auth-User", "admin") // the client's attempt
	_, seen := runForwardAuth(t, cfg, req)

	if got := seen.Get("X-Auth-User"); got != "alice" {
		t.Errorf("X-Auth-User = %q, want \"alice\" from the auth service", got)
	}
	if got := seen.Get("X-Auth-Roles"); got != "viewer" {
		t.Errorf("X-Auth-Roles = %q, want \"viewer\"", got)
	}
	if got := seen.Get("X-Not-Listed"); got != "" {
		t.Errorf("X-Not-Listed = %q; only allow-listed headers may be copied, or the "+
			"auth service can set anything on the backend request", got)
	}
}

// TestForwardAuthSendsTheForwardedContext covers the Traefik-style headers the
// auth service uses to make its decision.
func TestForwardAuthSendsTheForwardedContext(t *testing.T) {
	var got http.Header
	addr := authService(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/orders?id=7", nil)
	req.Host = "app.example.com"
	runForwardAuth(t, ForwardAuthConfig{Address: addr}, req)

	for h, want := range map[string]string{
		"X-Forwarded-Method": "POST",
		"X-Forwarded-Host":   "app.example.com",
		"X-Forwarded-Uri":    "/orders?id=7",
	} {
		if got.Get(h) != want {
			t.Errorf("%s = %q, want %q — the auth service decides on this context, "+
				"and a wrong method or path means it authorises the wrong request",
				h, got.Get(h), want)
		}
	}
}

// TestForwardAuthRestoresTheBodyForTheBackend covers forward_body.
func TestForwardAuthRestoresTheBodyForTheBackend(t *testing.T) {
	var authSaw string
	addr := authService(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		authSaw = string(b)
		w.WriteHeader(http.StatusOK)
	})

	const body = `{"amount":100}`
	mw, err := ForwardAuth(ForwardAuthConfig{Address: addr, ForwardBody: true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var backendSaw string
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		backendSaw = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/orders", strings.NewReader(body)))

	if authSaw != body {
		t.Errorf("the auth service read %q, want the body it is meant to inspect", authSaw)
	}
	if backendSaw != body {
		t.Errorf("the backend read %q, want %q — reading the body for the auth check "+
			"must not consume it", backendSaw, body)
	}
}

// TestForwardAuthStripsIdentityHeadersOnPreflightToo covers the one path that
// returns before the strip.
//
// A CORS preflight skips the auth call deliberately and correctly: a browser
// sends OPTIONS without credentials, so checking it would break every
// cross-origin request before the real one is ever made. But the early return
// sits above the loop that deletes client-supplied identity headers, so a
// preflight reaches the backend still carrying whatever the client put in
// X-Auth-User.
//
// Skipping the auth *call* on a preflight is right. Skipping the *strip* is a
// separate decision that nothing argues for: the backend is told these headers
// come from the auth service, and on this one path they come from the client.
// Anything the backend does with them on an OPTIONS request -- routing it to a
// real handler, recording it in an audit log, deciding which CORS headers to
// return -- it does on a forged identity.
func TestForwardAuthStripsIdentityHeadersOnPreflightToo(t *testing.T) {
	addr := authService(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	cfg := ForwardAuthConfig{
		Address:             addr,
		AuthResponseHeaders: []string{"X-Auth-User"},
	}

	req := httptest.NewRequest(http.MethodOptions, "/resource", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("X-Auth-User", "admin")

	rr, seen := runForwardAuth(t, cfg, req)
	if rr.Code != http.StatusOK || seen == nil {
		t.Fatalf("setup: the preflight should reach the backend; got %d", rr.Code)
	}

	if got := seen.Get("X-Auth-User"); got != "" {
		t.Errorf("a CORS preflight carried X-Auth-User: %q from the client to the "+
			"backend.\nThe preflight skips the auth call for a good reason — a "+
			"browser sends OPTIONS without credentials — but the early return also "+
			"skips the loop that clears client-supplied identity headers. The "+
			"backend is told this header comes from the auth service; on this path "+
			"it comes from whoever sent the request.", got)
	}
}
