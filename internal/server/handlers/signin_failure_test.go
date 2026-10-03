// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/api"
	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

// dbDownAPI fails every sign-in the way the service does when the user
// database does not answer: with the driver's error.
type dbDownAPI struct {
	GlobalAndAuthAPI
}

const driverError = "dial tcp 10.20.30.40:5432: connect: connection refused"

func (dbDownAPI) Login(context.Context, *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	return nil, errors.New(driverError)
}

// wrongPasswordAPI refuses the credentials.
type wrongPasswordAPI struct {
	GlobalAndAuthAPI
}

func (wrongPasswordAPI) Login(context.Context, *gateonv1.LoginRequest) (*gateonv1.LoginResponse, error) {
	return nil, auth.ErrInvalidCredentials
}

func postLogin(t *testing.T, svc GlobalAndAuthAPI) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, svc, &Deps{})
	req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader(`{"username":"alice","password":"pw"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, authWaived(req))
	return rr
}

// TestSignInWithTheUserDatabaseDownIsNotAWrongPassword: with the configuration
// Postgres stopped, every sign-in answered 401 -- which the dashboard shows as
// "Invalid username or password" -- carrying the driver's error, address and
// all, to a caller who has not signed in. It is the gateway that failed: 503,
// and the detail goes to the log.
func TestSignInWithTheUserDatabaseDownIsNotAWrongPassword(t *testing.T) {
	rr := postLogin(t, dbDownAPI{})
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("sign-in with the user database down answered %d, want 503", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "10.20.30.40") {
		t.Errorf("the answer names the database to an unauthenticated caller: %s", rr.Body.String())
	}
}

// TestSignInWithAWrongPasswordIsStill401 is the control.
func TestSignInWithAWrongPasswordIsStill401(t *testing.T) {
	if rr := postLogin(t, wrongPasswordAPI{}); rr.Code != http.StatusUnauthorized {
		t.Errorf("a wrong password answered %d, want 401", rr.Code)
	}
}

// TestSecondFactorUnderAnotherSessionKeyIsExplained: a user database restored
// with a different global.json holds second factors encrypted under another
// session key. The sign-in's second step answered the raw
// "failed to decrypt secret: cipher: message authentication failed".
func TestSecondFactorUnderAnotherSessionKeyIsExplained(t *testing.T) {
	const keyA, keyB = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	id := enrolSecondFactor(t, dbPath, keyA)

	mgr, err := auth.NewManager(dbPath, keyB, logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	_, _, err = mgr.Authenticate("gina", "correct-horse-battery")
	if !errors.Is(err, auth.ErrTwoFactorRequired) {
		t.Fatalf("password step: %v", err)
	}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, api.NewApiService(api.ApiServiceConfig{Auth: mgr}), &Deps{})
	body := `{"id":"` + id + `","code":"123456","challenge":"` + auth.ChallengeFrom(err) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, authWaived(req))

	if strings.Contains(rr.Body.String(), "cipher") {
		t.Errorf("the second step answered the raw decryption error: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "different session key") {
		t.Errorf("the answer does not say why the second factor cannot be read: %s", rr.Body.String())
	}
}

// enrolSecondFactor creates an account on dbPath with a second factor
// encrypted under key, and returns its id.
func enrolSecondFactor(t *testing.T, dbPath, key string) string {
	t.Helper()
	m, err := auth.NewManager(dbPath, key, logger.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	u := &gateonv1.User{Username: "gina", Password: "correct-horse-battery", Role: auth.RoleAdmin}
	if err := m.UpsertUser(u); err != nil {
		t.Fatal(err)
	}
	enrolment, err := m.Setup2FA(u.Id, "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrolment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _, err := m.Verify2FA(enrolment.Challenge, u.Id, code); err != nil || !ok {
		t.Fatalf("enrolling: ok=%v err=%v", ok, err)
	}
	return u.Id
}
