// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// Both brute-force detectors read what the Metrics middleware records when a
// request finishes: the anomaly detector the aggregator's refused attempts,
// the per-IP detector the trace. A POST refused 401 counted as an attempt
// whatever it carried, so a Connect or GraphQL client whose session or token
// expired -- the dashboard's own tab among them -- read as password guessing.
// When the gateway's own verification refused the token the request
// presented, the refusing middleware marks the request, and Metrics hands the
// mark to both. ADR 0031.

// expiredSessions verifies no token, as the management plane's verifier does
// once a session has expired.
type expiredSessions struct{}

func (expiredSessions) VerifyToken(string) (any, error) { return nil, errors.New("token expired") }

// answer200 is the origin behind an authentication middleware: reached only
// when the middleware let the request through.
var answer200 = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// answer401 is a handler that refuses every request itself: the login form
// refusing a password, or a backend refusing whatever it was sent.
var answer401 = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusUnauthorized)
})

// backend401 is answer401 as a route serves it, behind the router's service
// boundary: a backend's answer, which the gateway cannot read into.
var backend401 = request.ServiceBoundary(answer401)

func expiredJWT(t *testing.T, secret []byte) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "poller", "exp": time.Now().Add(-time.Hour).Unix(),
	}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// countedRefusal serves one request from ip through Metrics and h, with the
// request state the entrypoint gives every request, and returns the status and
// how many refused credential attempts the aggregator counted for it.
func countedRefusal(h http.Handler, ip, method, path string, header map[string]string) (int, float64) {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = ip + ":51000"
	for k, v := range header {
		req.Header.Set(k, v)
	}
	// The request id is the trace's; the entrypoint's telemetry sets one.
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{RequestID: request.GenerateID()}))
	before := refusedAttempts(ip)
	rr := httptest.NewRecorder()
	Metrics("token-refusal")(h).ServeHTTP(rr, req)
	return rr.Code, refusedAttempts(ip) - before
}

func TestTheGatewaysOwnTokenRefusalIsNotACredentialAttempt(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	jwtAuth, err := NewJWTValidator(JWTConfig{Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	session := PasetoAuth(expiredSessions{}, AuthBaseConfig{})(answer200)
	apiKey := NewAPIKeyValidator(NewMemoryAPIKeyStore(map[string]string{"live-key": "tenant"}, false), "", "", AuthBaseConfig{})
	for _, tc := range []struct {
		name, ip, method, path string
		h                      http.Handler
		header                 map[string]string
		want                   float64
	}{
		{"the dashboard's Connect poll with an expired session", "198.51.100.200", http.MethodPost,
			"/gateon.v1.ApiService/GetMetricsSnapshot", session,
			map[string]string{"Cookie": "gateon_session=expired", "Content-Type": "application/json"}, 0},
		{"a GraphQL poll with an expired JWT", "198.51.100.201", http.MethodPost, "/graphql",
			jwtAuth.Handler(answer200), map[string]string{"Authorization": "Bearer " + expiredJWT(t, secret)}, 0},
		{"a POST with a revoked API key", "198.51.100.202", http.MethodPost, "/api/orders",
			apiKey.Handler(answer200), map[string]string{"X-API-Key": "revoked-key"}, 0},
		{"stuffing /v1/login with a bogus bearer header", "198.51.100.203", http.MethodPost, "/v1/login",
			backend401, map[string]string{"Authorization": "Bearer x", "Content-Type": "application/json"}, 1},
		{"Basic auth guessed over GET", "198.51.100.204", http.MethodGet, "/reports",
			BasicAuth("admin", "right-password")(answer200), map[string]string{"Authorization": "Basic YWRtaW46Z3Vlc3M="}, 1},
		{"a backend's own 401 to a POST (the gateway cannot know)", "198.51.100.205", http.MethodPost, "/api/orders",
			backend401, map[string]string{"Authorization": "Bearer expired"}, 1},
		// Only a token the gateway checked is a token refusal: a POST that
		// presented none was refused for that, not for a stale session.
		{"a POST presenting no token to the session check", "198.51.100.206", http.MethodPost,
			"/gateon.v1.ApiService/ListRoutes", session, map[string]string{"Content-Type": "application/json"}, 1},
		// In dry run the check refuses nothing; the backend's refusal is its own.
		{"a dry-run session check in front of a backend that refuses", "198.51.100.207", http.MethodPost, "/v1/login",
			PasetoAuth(expiredSessions{}, AuthBaseConfig{DryRun: true})(backend401),
			map[string]string{"Authorization": "Bearer stale"}, 1},
	} {
		code, got := countedRefusal(tc.h, tc.ip, tc.method, tc.path, tc.header)
		if code != http.StatusUnauthorized {
			t.Fatalf("%s: answered %d, want 401; the case proves nothing", tc.name, code)
		}
		if got != tc.want {
			t.Errorf("%s refused 401: %v refused credential attempts counted, want %v", tc.name, got, tc.want)
		}
	}
}

// The per-IP detector reads the trace, so the mark has to reach it.
func TestATokenRefusalIsTracedAsOne(t *testing.T) {
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(t.TempDir(), "traces"))
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "telemetry.db"), 1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	session := PasetoAuth(expiredSessions{}, AuthBaseConfig{})(answer200)
	const poller, stuffer = "198.51.100.210", "198.51.100.211"
	countedRefusal(session, poller, http.MethodPost, "/gateon.v1.ApiService/ListRoutes",
		map[string]string{"Cookie": "gateon_session=expired"})
	countedRefusal(backend401, stuffer, http.MethodPost, "/v1/login", map[string]string{"Authorization": "Bearer x"})
	telemetry.FlushTraces()

	refusals := map[string]string{}
	for _, tr := range telemetry.GetTracesFiltered(t.Context(), 100, true) {
		refusals[tr.SourceIP] = tr.Refusal
	}
	if got, ok := refusals[poller]; !ok || got != "token" {
		t.Errorf("the expired-session poll's trace records refusal %q (traced: %v), want \"token\"", got, ok)
	}
	if got, ok := refusals[stuffer]; !ok || got != "" {
		t.Errorf("the login stuffing's trace records refusal %q (traced: %v), want none", got, ok)
	}
}
