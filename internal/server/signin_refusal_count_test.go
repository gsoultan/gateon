// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/server/handlers"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The management plane reaches no route's service, so since ADR 0059 a 401 it
// writes counts towards brute force only when sign-in marked it as a refused
// credential (request.RefusalAuthentication). Without the mark, password and
// second-factor guessing against the dashboard would not be counted at all.

// signInPlane is the management REST API behind the entrypoint's Metrics, and
// the manager behind it, with an administrator whose second factor is on.
func signInPlane(t *testing.T) (http.Handler, *api.ApiService, string) {
	t.Helper()
	t.Setenv("GATEON_ENCRYPTION_KEY", "")
	dir := t.TempDir()
	mgr, err := auth.NewManager(filepath.Join(dir, "auth.db"), "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if err := mgr.UpsertUser(&gateonv1.User{Username: "admin", Password: anonAdminPassword, Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	_, user, err := mgr.Authenticate("admin", anonAdminPassword, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	enrolment, err := mgr.Setup2FA(user.Id, anonAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrolment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _, err := mgr.Verify2FA(enrolment.Challenge, user.Id, code); !ok || err != nil {
		t.Fatalf("enable 2FA: ok=%v err=%v", ok, err)
	}
	svc := &api.ApiService{Auth: mgr, Globals: config.NewGlobalRegistry(filepath.Join(dir, "global.json"))}
	mux := http.NewServeMux()
	handlers.RegisterRESTHandlers(mux, svc, &handlers.Deps{AuthManager: mgr})
	return middleware.Metrics("gateon-management")(mux), svc, user.Id
}

func TestAManagementSignInRefusalIsACredentialAttempt(t *testing.T) {
	h, _, _ := signInPlane(t)
	for _, tc := range []struct{ name, ip, path string }{
		{"a wrong password", "198.51.100.250", "/v1/login"},
		{"a wrong password to first-time enrolment", "198.51.100.252", "/v1/auth/2fa/enroll"},
	} {
		before := authFailures(tc.ip)
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{"username":"admin","password":"a-guess"}`))
		req.RemoteAddr = tc.ip + ":51000"
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(request.WithState(req.Context(), &request.RequestState{ClientRemoteAddr: tc.ip}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: answered %d (%s), want 401; the case proves nothing", tc.name, rr.Code, rr.Body.String())
		}
		if got := authFailures(tc.ip) - before; got != 1 {
			t.Errorf("%s refused 401: %v refused credential attempts counted, want 1", tc.name, got)
		}
	}
}

// TestAWrongSecondFactorCodeIsMarkedAsAnAuthenticationRefusal: the second
// step of a sign-in is served over REST and Connect by the same service
// method, which marks the refusal for whichever transport carried it.
func TestAWrongSecondFactorCodeIsMarkedAsAnAuthenticationRefusal(t *testing.T) {
	_, svc, id := signInPlane(t)
	_, _, err := svc.Auth.Authenticate("admin", anonAdminPassword, "192.0.2.2")
	challenge := auth.ChallengeFrom(err)
	if challenge == "" {
		t.Fatalf("the right password did not earn a second-factor challenge: %v", err)
	}
	rs := &request.RequestState{ClientRemoteAddr: "198.51.100.251"}
	ctx := request.WithState(t.Context(), rs)
	if _, err := svc.Verify2FA(ctx, &gateonv1.Verify2FARequest{Id: id, Code: "000000", Challenge: challenge}); err == nil {
		t.Fatal("a wrong code was accepted")
	}
	if rs.Refused != request.RefusalAuthentication {
		t.Errorf("a wrong second-factor code is marked %q, want %q", rs.Refused, request.RefusalAuthentication)
	}
}

// authFailures is what the anomaly detector's brute-force check reads for ip.
func authFailures(ip string) float64 {
	for _, s := range telemetry.GetAggregator().GetIPStats(0) {
		if s.IP == ip {
			return s.AuthFail
		}
	}
	return 0
}
