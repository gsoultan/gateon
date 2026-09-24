// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/transform"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"
)

// The middleware factory hands every middleware the route it is being built
// for under the config key "route_id". Three consumers read it back as
// "_route_id" -- the name the key had until a rename that updated the writer
// and none of the readers -- so each of them has run with an empty route ID
// ever since:
//
//   - oidc names its state, origin and session cookies after the route. The
//     half that starts a login wrote "gateon_state_" while the callback looked
//     for "gateon_state_<route>", so no login could complete: every user was
//     sent to the provider and came back to a 400 "Invalid state".
//   - bot_management labelled its metrics and threats with an empty route, so
//     the dashboard could not say which route challenged or refused anyone.
//   - file_security filed its malware blocks against no route.
//
// These tests drive the real route chain (HandleProxyOrLocal -> router ->
// factory) rather than the factory alone, because the defect lived exactly in
// the hand-off between the two.

// routeIdentityGateway builds a server whose only route is rt, fronting
// backend, with mw registered, and returns the handler the entrypoints use.
func routeIdentityGateway(t *testing.T, backend string, rt *gateonv1.Route, mw *gateonv1.Middleware) http.Handler {
	t.Helper()
	dir := t.TempDir()
	s, err := NewServer(
		WithRouteRegistry(config.NewRouteRegistry(filepath.Join(dir, "routes.json"))),
		WithServiceRegistry(config.NewServiceRegistry(filepath.Join(dir, "services.json"))),
		WithEntryPointRegistry(config.NewEntryPointRegistry(filepath.Join(dir, "entrypoints.json"))),
		WithMiddlewareRegistry(config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))),
		WithTLSOptionRegistry(config.NewTLSOptionRegistry(filepath.Join(dir, "tls_options.json"))),
		WithGlobalRegistry(config.NewGlobalRegistry(filepath.Join(dir, "global.json"))),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	svc := &gateonv1.Service{Id: "svc", Name: "svc", WeightedTargets: []*gateonv1.Target{{Url: backend, Weight: 1}}}
	if err := s.ServiceStore.Update(t.Context(), svc); err != nil {
		t.Fatalf("store service: %v", err)
	}
	if err := s.MwStore.Update(t.Context(), mw); err != nil {
		t.Fatalf("store middleware: %v", err)
	}
	rt.ServiceId = svc.Id
	rt.Middlewares = []string{mw.Id}
	if err := s.RouteStore.Update(t.Context(), rt); err != nil {
		t.Fatalf("store route: %v", err)
	}
	local := transform.NewDefaultGRPCWebDetector(grpc.NewServer())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleProxyOrLocal(w, r, local, local, http.NewServeMux())
	})
}

// fakeOIDCProvider answers discovery, JWKS and the token endpoint. Any
// authorization code is exchanged for an ID token whose subject is "user-42".
func fakeOIDCProvider(t *testing.T, clientID string) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": srv.URL, "aud": clientID, "sub": "user-42",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		idToken.Header["kid"] = "k1"
		signed, err := idToken.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"access_token": "opaque", "token_type": "Bearer", "expires_in": 3600, "id_token": signed,
		})
	})
	return srv
}

func serveRecorded(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestOIDCLoginCompletesThroughTheRouteChain walks the whole relying-party
// flow: redirect to the provider, the provider's redirect back to the
// callback, and the session reaching the backend with the verified identity.
func TestOIDCLoginCompletesThroughTheRouteChain(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "user="+r.Header.Get("X-Forwarded-User"))
	}))
	defer backend.Close()
	provider := fakeOIDCProvider(t, "gateon-app")

	gw := routeIdentityGateway(t, backend.URL,
		&gateonv1.Route{Id: "app-route", Rule: "PathPrefix(`/`)", Type: "http"},
		&gateonv1.Middleware{Id: "login", Name: "login", Type: "oidc", Config: map[string]string{
			"issuer":        provider.URL,
			"client_id":     "gateon-app",
			"client_secret": "s3cret",
			"redirect_url":  "http://app.test/_gateon/oidc/callback/app-route",
		}})

	// 1. Unauthenticated: sent to the provider, carrying a CSRF state cookie.
	start := serveRecorded(gw, httptest.NewRequest(http.MethodGet, "http://app.test/account", nil))
	if start.Code != http.StatusFound {
		t.Fatalf("unauthenticated request: status %d, want 302 to the provider; body %q", start.Code, start.Body.String())
	}
	loc, err := url.Parse(start.Header().Get("Location"))
	if err != nil || loc.Query().Get("state") == "" {
		t.Fatalf("redirect %q carries no state", start.Header().Get("Location"))
	}

	// 2. The provider sends the user back with the state and a code.
	cb := httptest.NewRequest(http.MethodGet, "http://app.test/_gateon/oidc/callback/app-route?code=authcode&state="+
		url.QueryEscape(loc.Query().Get("state")), nil)
	for _, c := range start.Result().Cookies() {
		cb.AddCookie(c)
	}
	back := serveRecorded(gw, cb)
	if back.Code != http.StatusFound {
		t.Fatalf("callback: status %d body %q, want 302 back to the app; cookies set by the first "+
			"leg were %v, so the callback is looking for a state cookie under a name the first leg never used",
			back.Code, back.Body.String(), cookieNames(start.Result().Cookies()))
	}
	// The cookie's suffix is derived from the route label, hashed so that a
	// display name with a space still makes a valid cookie name; what matters
	// here is that the callback set a session and that step 3 accepts it.
	var session *http.Cookie
	for _, c := range back.Result().Cookies() {
		if strings.HasPrefix(c.Name, "gateon_session_") && c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatalf("callback set no session cookie; got %v", cookieNames(back.Result().Cookies()))
	}

	// 3. The session reaches the backend as the verified user.
	app := httptest.NewRequest(http.MethodGet, "http://app.test/account", nil)
	app.AddCookie(session)
	got := serveRecorded(gw, app)
	if got.Code != http.StatusOK || got.Body.String() != "user=user-42" {
		t.Fatalf("authenticated request: status %d body %q, want 200 %q", got.Code, got.Body.String(), "user=user-42")
	}
}

func cookieNames(cs []*http.Cookie) []string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name)
	}
	return names
}

// TestBotManagementCountsAgainstItsRoute checks the route label on the
// challenge metric. An empty label is what the dashboard showed for every
// route that challenged a client.
func TestBotManagementCountsAgainstItsRoute(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer backend.Close()

	gw := routeIdentityGateway(t, backend.URL,
		&gateonv1.Route{Id: "bot-route", Rule: "PathPrefix(`/`)", Type: "http"},
		&gateonv1.Middleware{Id: "bots", Name: "bots", Type: "bot_management", Config: map[string]string{
			"enabled": "true", "enable_js_challenge": "true", "secret_key": "route-identity-test",
		}})

	before := botChallengesServed(t, "bot-route")

	rec := serveRecorded(gw, httptest.NewRequest(http.MethodGet, "http://bot.test/", nil))
	if rec.Body.String() == "origin" {
		t.Fatal("request reached the origin: bot management is not in the route chain, so this test proves nothing")
	}
	if got := botChallengesServed(t, "bot-route") - before; got != 1 {
		t.Fatalf("challenge_served for route %q rose by %v, want 1: the challenge was counted against another route label",
			"bot-route", got)
	}
}

// TestFileSecurityFilesItsBlocksAgainstItsRoute uploads a file over the size
// cap and reads the resulting threat off the live feed the Security Hub uses.
func TestFileSecurityFilesItsBlocksAgainstItsRoute(t *testing.T) {
	dir := t.TempDir()
	_ = telemetry.ClosePathStatsStore(t.Context())
	if err := telemetry.InitPathStatsStore("sqlite://"+filepath.Join(dir, "telemetry.db"), 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	feed := telemetry.ThreatBroadcaster.Subscribe()
	defer telemetry.ThreatBroadcaster.Unsubscribe(feed)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "origin")
	}))
	defer backend.Close()
	gw := routeIdentityGateway(t, backend.URL,
		&gateonv1.Route{Id: "upload-route", Rule: "PathPrefix(`/`)", Type: "http"},
		&gateonv1.Middleware{Id: "files", Name: "files", Type: "file_security", Config: map[string]string{
			"max_file_size": "16", "enable_signature_scan": "false",
		}})

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "big.txt")
	_, _ = part.Write(bytes.Repeat([]byte("a"), 64))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "http://files.test/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if rec := serveRecorded(gw, req); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload: status %d body %q, want 413 from file_security", rec.Code, rec.Body.String())
	}

	// The store loop publishes the threat asynchronously; wait for it on the
	// feed itself rather than on a timer.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case th := <-feed:
			if th.Type != "file_security_block" {
				continue
			}
			if th.RouteID != "upload-route" {
				t.Fatalf("file_security threat filed against route %q, want %q", th.RouteID, "upload-route")
			}
			return
		case <-deadline:
			t.Fatal("no file_security_block threat reached the live feed")
		}
	}
}

// botChallengesServed reads the challenge counter for one route through the
// collector, which keeps prometheus/testutil out of go.mod.
func botChallengesServed(t *testing.T, route string) float64 {
	t.Helper()
	c, err := telemetry.MiddlewareBotManagementTotal.GetMetricWithLabelValues(route, "challenge_served")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}
