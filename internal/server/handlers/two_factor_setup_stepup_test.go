// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
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

const stepUpPassword = "right-pass"

// stepUpFixture is the real 2FA stack behind POST /v1/auth/2fa/setup: the
// handler, ApiService and an auth.Manager on a throwaway SQLite database.
type stepUpFixture struct {
	mux *http.ServeMux
	m   *auth.Manager
	id  string
}

func newStepUpFixture(t *testing.T) stepUpFixture {
	t.Helper()
	m, err := auth.NewManager(filepath.Join(t.TempDir(), "auth.db"),
		"0123456789abcdef0123456789abcdef", logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	u := &gateonv1.User{Username: "alice", Password: stepUpPassword, Role: auth.RoleAdmin}
	if err := m.UpsertUser(u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, &api.ApiService{Auth: m}, &Deps{})
	return stepUpFixture{mux: mux, m: m, id: u.Id}
}

// setup posts body to the setup endpoint as the account itself -- the only
// caller the endpoint serves.
func (f stepUpFixture) setup(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	self := &auth.Claims{ID: f.id, Username: "alice", Role: auth.RoleAdmin}
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, authWaived(claimsRequest(t, "/v1/auth/2fa/setup", body, self)))
	return rr
}

func (f stepUpFixture) body(password string) string {
	if password == "" {
		return `{"id":"` + f.id + `"}`
	}
	return `{"id":"` + f.id + `","password":"` + password + `"}`
}

// assertNothingDisclosed fails if the response carries any enrolment material.
func assertNothingDisclosed(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	for _, key := range []string{"secret", "qrCodeUrl", "recoveryCodes"} {
		if strings.Contains(rr.Body.String(), `"`+key+`"`) {
			t.Errorf("refused setup disclosed %s: %s", key, rr.Body.String())
		}
	}
}

// TestTwoFactorSetupRefusesAMissingPassword: setup asked only for the session,
// and the dashboard's session is a cookie script in the page can ride. So a
// stored-XSS payload could call setup, keep the secret, verify a code derived
// from it and own the account's second factor.
func TestTwoFactorSetupRefusesAMissingPassword(t *testing.T) {
	f := newStepUpFixture(t)
	rr := f.setup(t, f.body(""))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertNothingDisclosed(t, rr)
}

// TestTwoFactorSetupCountsWrongPasswordsLikeSignIn: a wrong password is
// refused -- with 403, which the dashboard does not read as "signed out" --
// and counted, so the prompt cannot be used to guess the password past the
// lockout; after the limit even the right one is refused.
func TestTwoFactorSetupCountsWrongPasswordsLikeSignIn(t *testing.T) {
	f := newStepUpFixture(t)
	for i := range auth.MaxFailedAttempts {
		rr := f.setup(t, f.body("wrong-pass"))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("wrong password %d: status %d, want 403: %s", i+1, rr.Code, rr.Body.String())
		}
		assertNothingDisclosed(t, rr)
	}
	rr := f.setup(t, f.body(stepUpPassword))
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("right password on a locked account: status %d, want 429: %s", rr.Code, rr.Body.String())
	}
	assertNothingDisclosed(t, rr)
	if _, _, err := f.m.Authenticate("alice", stepUpPassword); !errors.Is(err, auth.ErrAccountLocked) {
		t.Errorf("sign-in after %d wrong step-up passwords: err = %v, want ErrAccountLocked", auth.MaxFailedAttempts, err)
	}
}

// TestTwoFactorSetupWithThePasswordStillEnrols pins the path the fix keeps.
func TestTwoFactorSetupWithThePasswordStillEnrols(t *testing.T) {
	f := newStepUpFixture(t)
	secret := f.enrol(t)
	if secret == "" {
		t.Fatal("setup with the right password returned no secret")
	}
}

// enrol completes a real enrolment through the endpoints and returns the
// secret the account's authenticator now holds.
func (f stepUpFixture) enrol(t *testing.T) string {
	t.Helper()
	rr := f.setup(t, f.body(stepUpPassword))
	if rr.Code != http.StatusOK {
		t.Fatalf("setup with the right password: status %d: %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Secret        string   `json:"secret"`
		QRCodeURL     string   `json:"qrCodeUrl"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.QRCodeURL == "" || len(got.RecoveryCodes) == 0 {
		t.Fatalf("setup answered without a QR code or recovery codes: %s", rr.Body.String())
	}
	code, err := totp.GenerateCode(got.Secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if ok, _, _, err := f.m.Verify2FA(f.id, code); !ok || err != nil {
		t.Fatalf("Verify2FA: ok=%v err=%v", ok, err)
	}
	return got.Secret
}

// TestTwoFactorSetupRefusedKeepsTheOwnersFactor: setup replaces the stored
// secret and turns 2FA off until the new one is verified, so a setup let
// through without the password took the second factor away from its owner.
func TestTwoFactorSetupRefusedKeepsTheOwnersFactor(t *testing.T) {
	f := newStepUpFixture(t)
	secret := f.enrol(t)

	for _, password := range []string{"", "wrong-pass"} {
		rr := f.setup(t, f.body(password))
		if rr.Code == http.StatusOK {
			t.Errorf("setup with password %q was served: %s", password, rr.Body.String())
		}
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if ok, _, _, err := f.m.Verify2FA(f.id, code); !ok || err != nil {
		t.Errorf("the owner's authenticator stopped verifying: ok=%v err=%v", ok, err)
	}
	if _, _, err := f.m.Authenticate("alice", stepUpPassword); !errors.Is(err, auth.ErrTwoFactorRequired) {
		t.Errorf("sign-in no longer asks for the second factor: err = %v", err)
	}
}

// wrongCodeAPI refuses every code, as the service does a mistyped one.
type wrongCodeAPI struct {
	GlobalAndAuthAPI
}

func (wrongCodeAPI) Verify2FA(context.Context, *gateonv1.Verify2FARequest) (*gateonv1.Verify2FAResponse, error) {
	return nil, auth.ErrInvalidTwoFactorCode
}

// TestTwoFactorEnrolmentWrongCodeIsNotASignOut: the dashboard's apiFetch reads
// any 401 as "the session is over" and signs the user out, and verify answered
// a mistyped code with 401 -- so a typo in the enrolment dialog ended the
// session of a user who was only trying to protect it. During sign-in there is
// no session and 401 stays.
func TestTwoFactorEnrolmentWrongCodeIsNotASignOut(t *testing.T) {
	mux := http.NewServeMux()
	registerGlobalHandlers(mux, wrongCodeAPI{}, &Deps{})

	self := &auth.Claims{ID: "the-user", Username: "user", Role: auth.RoleViewer}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, authWaived(claimsRequest(t, "/v1/auth/2fa/verify", `{"id":"the-user","code":"000000"}`, self)))
	if rr.Code != http.StatusForbidden {
		t.Errorf("signed-in enrolment, wrong code: status %d, want 403", rr.Code)
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/verify", strings.NewReader(`{"id":"the-user","code":"000000"}`))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rr, authWaived(req))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("sign-in step, wrong code: status %d, want 401", rr.Code)
	}
}
