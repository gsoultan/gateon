// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/testutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// createOIDC builds the oidc middleware the way the router does — through the
// factory, with the route label the router passes, which is the route's
// display name and so may contain a space.
func createOIDC(t *testing.T, issuer, redirectURL string) (Middleware, error) {
	t.Helper()
	f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
	return f.Create(&gateonv1.Middleware{
		Id:   "oidc-login",
		Type: "oidc",
		Config: map[string]string{
			"issuer":        issuer,
			"client_id":     "gateon-client",
			"client_secret": "secret",
			"redirect_url":  redirectURL,
		},
	}, "My App")
}

// buildOIDCRoute wraps a backend that echoes the identity the middleware
// forwarded.
func buildOIDCRoute(t *testing.T, idp *testutil.FakeOIDCProvider, redirectURL string) http.Handler {
	t.Helper()
	mw, err := createOIDC(t, idp.Issuer(), redirectURL)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.Header.Get("X-Forwarded-User")))
	}))
}

// browse sends one request carrying the jar's cookies and folds the response's
// Set-Cookie headers back into the jar, which is all of a browser this flow
// needs.
func browse(t *testing.T, h http.Handler, jar map[string]string, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for name, value := range jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(jar, c.Name)
			continue
		}
		jar[c.Name] = c.Value
	}
	return rec
}

// TestOIDCLoginCompletesThroughTheFactory walks the whole authorization-code
// flow a browser performs against a route protected by the oidc middleware,
// using the callback URL shape the dashboard suggests.
//
// It failed at the callback with "400 Invalid state": the factory read the
// route id from a config key nothing writes, so the middleware named its
// cookies with an empty suffix, while the callback derived "global" from any
// redirect path outside /_gateon/oidc/callback/ and looked for cookies that
// had never been set. No login could complete.
func TestOIDCLoginCompletesThroughTheFactory(t *testing.T) {
	idp := testutil.NewFakeOIDCProvider(t, "gateon-client")
	h := buildOIDCRoute(t, idp, "https://app.example.com/auth/callback")
	jar := map[string]string{}

	rec := browse(t, h, jar, "https://app.example.com/dashboard?tab=2")
	if rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated request: status %d, want 302 to the provider; body %q", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), idp.Issuer()+"/authorize") {
		t.Fatalf("redirect %q does not go to the provider's authorize endpoint", rec.Header().Get("Location"))
	}
	state := loc.Query().Get("state")

	rec = browse(t, h, jar, "https://app.example.com/auth/callback?code=abc&state="+url.QueryEscape(state))
	if rec.Code != http.StatusFound {
		t.Fatalf("callback: status %d, want 302 back to the app; body %q", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Location"); got != "/dashboard?tab=2" {
		t.Fatalf("callback returned the user to %q, want the page they asked for", got)
	}

	rec = browse(t, h, jar, "https://app.example.com/dashboard?tab=2")
	if rec.Code != http.StatusOK || rec.Body.String() != "hello user-1" {
		t.Fatalf("after login: status %d body %q, want 200 %q", rec.Code, rec.Body, "hello user-1")
	}
}

// TestOIDCCallbackRejectsAForgedState keeps the CSRF half of the flow honest
// once the cookie names line up: a state the gateway did not issue must still
// be refused.
func TestOIDCCallbackRejectsAForgedState(t *testing.T) {
	idp := testutil.NewFakeOIDCProvider(t, "gateon-client")
	h := buildOIDCRoute(t, idp, "https://app.example.com/auth/callback")
	jar := map[string]string{}
	if rec := browse(t, h, jar, "https://app.example.com/"); rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated request: status %d, want 302", rec.Code)
	}
	rec := browse(t, h, jar, "https://app.example.com/auth/callback?code=abc&state=forged")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged state: status %d, want 400", rec.Code)
	}
}

// login runs the authorization-code flow for one route and fails the test if
// it does not end authenticated.
func login(t *testing.T, h http.Handler, jar map[string]string, page string) {
	t.Helper()
	rec := browse(t, h, jar, page)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil {
		t.Fatalf("login to %s: status %d, want 302 to the provider", page, rec.Code)
	}
	cb := "https://app.example.com/auth/callback?code=abc&state=" + url.QueryEscape(loc.Query().Get("state"))
	if rec = browse(t, h, jar, cb); rec.Code != http.StatusFound {
		t.Fatalf("callback for %s: status %d body %q", page, rec.Code, rec.Body)
	}
}

// TestOIDCRoutesOnOneHostKeepSeparateSessions logs a browser into two routes on
// the same host, each protected by its own oidc client. Their cookies must not
// collide: with no route id reaching the middleware every route named its
// cookies identically, so logging into the second route overwrote the first
// route's session with a token issued to another client, and the first route
// then refused it and sent the user round again.
func TestOIDCRoutesOnOneHostKeepSeparateSessions(t *testing.T) {
	build := func(clientID, label string) http.Handler {
		idp := testutil.NewFakeOIDCProvider(t, clientID)
		f := NewFactory(nil, &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{}}, nil, nil, t.TempDir())
		mw, err := f.Create(&gateonv1.Middleware{Id: "oidc-" + clientID, Type: "oidc", Config: map[string]string{
			"issuer": idp.Issuer(), "client_id": clientID, "client_secret": "s",
			"redirect_url": "https://app.example.com/auth/callback",
		}}, label)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(label))
		}))
	}
	billing, reports := build("billing-client", "Billing"), build("reports-client", "Reports")
	jar := map[string]string{}
	login(t, billing, jar, "https://app.example.com/billing")
	login(t, reports, jar, "https://app.example.com/reports")

	if rec := browse(t, billing, jar, "https://app.example.com/billing"); rec.Code != http.StatusOK {
		t.Fatalf("billing after logging into reports: status %d, want 200 — the second login replaced its session", rec.Code)
	}
}

// TestOIDCConstructionDoesNotWaitForTheProvider builds the middleware against
// an issuer that accepts the connection and never answers.
//
// Construction used to run provider discovery on http.DefaultClient, which has
// no timeout, and the proxy cache builds chains while holding its write lock:
// one unresponsive provider stalled the first request of every other route
// and every invalidation, gateway-wide, for as long as the provider hung.
func TestOIDCConstructionDoesNotWaitForTheProvider(t *testing.T) {
	hung := testutil.HungServer(t)
	done := make(chan error, 1)
	go func() {
		_, err := createOIDC(t, hung.URL, "https://app.example.com/auth/callback")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Create against a slow provider: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Create blocked on the provider's discovery endpoint")
	}
}
