// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const newPassword = "brand-new-pass"

// as posts body to path as the fixture's own account, alice.
func (f stepUpFixture) as(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	self := &auth.Claims{ID: f.id, Username: "alice", Role: auth.RoleAdmin}
	req := claimsRequest(t, path, body, self)
	req.Method = method
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	return rr
}

// assertPassword fails unless the account signs in with want and not with the
// other password the test used.
func (f stepUpFixture) assertPassword(t *testing.T, username, want, not string) {
	t.Helper()
	if _, _, err := f.m.Authenticate(username, want); err != nil {
		t.Errorf("%s cannot sign in with %q: %v", username, want, err)
	}
	if _, _, err := f.m.Authenticate(username, not); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("%s signing in with %q: err = %v, want ErrInvalidCredentials", username, not, err)
	}
}

// TestOwnPasswordChangeRefusesAMissingCurrentPassword: changing your own
// password needed only the session, and in the dashboard the session is a
// cookie script in the page can ride -- so a stored-XSS payload could set a
// password of its choosing, one that outlives the session it came from.
func TestOwnPasswordChangeRefusesAMissingCurrentPassword(t *testing.T) {
	f := newStepUpFixture(t)
	rr := f.as(t, http.MethodPost, "/v1/users/password", `{"id":"`+f.id+`","password":"`+newPassword+`"}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400: %s", rr.Code, rr.Body.String())
	}
	f.assertPassword(t, "alice", stepUpPassword, newPassword)
}

// TestOwnPasswordChangeCountsWrongPasswordsLikeSignIn: a wrong current
// password is refused with 403 -- not 401, which the dashboard reads as "signed
// out" -- and counted against the sign-in lockout, after which even the right
// one is refused.
func TestOwnPasswordChangeCountsWrongPasswordsLikeSignIn(t *testing.T) {
	f := newStepUpFixture(t)
	body := `{"id":"` + f.id + `","password":"` + newPassword + `","currentPassword":"wrong-pass"}`
	for i := range auth.MaxFailedAttempts {
		if rr := f.as(t, http.MethodPost, "/v1/users/password", body); rr.Code != http.StatusForbidden {
			t.Fatalf("wrong current password %d: status %d, want 403: %s", i+1, rr.Code, rr.Body.String())
		}
	}
	right := `{"id":"` + f.id + `","password":"` + newPassword + `","currentPassword":"` + stepUpPassword + `"}`
	if rr := f.as(t, http.MethodPost, "/v1/users/password", right); rr.Code != http.StatusTooManyRequests {
		t.Errorf("right password on a locked account: status %d, want 429: %s", rr.Code, rr.Body.String())
	}
	if _, _, err := f.m.Authenticate("alice", stepUpPassword); !errors.Is(err, auth.ErrAccountLocked) {
		t.Errorf("sign-in after %d wrong current passwords: err = %v, want ErrAccountLocked", auth.MaxFailedAttempts, err)
	}
}

// TestOwnPasswordChangeWithTheCurrentPasswordWorks pins the path the fix keeps.
func TestOwnPasswordChangeWithTheCurrentPasswordWorks(t *testing.T) {
	f := newStepUpFixture(t)
	body := `{"id":"` + f.id + `","password":"` + newPassword + `","currentPassword":"` + stepUpPassword + `"}`
	if rr := f.as(t, http.MethodPost, "/v1/users/password", body); rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	f.assertPassword(t, "alice", newPassword, stepUpPassword)
}

// TestAdminResetOfAnotherAccountKeepsTodaysRule: an administrator resetting
// someone else's password has no current password to give, and still needs
// none.
func TestAdminResetOfAnotherAccountKeepsTodaysRule(t *testing.T) {
	f := newStepUpFixture(t)
	bob := &gateonv1.User{Username: "bob", Password: "bobs-pass", Role: auth.RoleViewer}
	if err := f.m.UpsertUser(bob); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	rr := f.as(t, http.MethodPost, "/v1/users/password", `{"id":"`+bob.Id+`","password":"`+newPassword+`"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	f.assertPassword(t, "bob", newPassword, "bobs-pass")
}

// TestEditingYourselfCannotSetYourPassword: PUT /v1/users writes a password
// when the body has one, so the step-up above could be walked around by editing
// your own account as a user -- by id, or by a fresh id with your username,
// which the upsert resolves to your account all the same.
func TestEditingYourselfCannotSetYourPassword(t *testing.T) {
	f := newStepUpFixture(t)
	for name, body := range map[string]string{
		"by id":       `{"id":"` + f.id + `","username":"alice","role":"admin","password":"` + newPassword + `"}`,
		"by username": `{"id":"another-id","username":"alice","role":"admin","password":"` + newPassword + `"}`,
	} {
		rr := f.as(t, http.MethodPut, "/v1/users", body)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403: %s", name, rr.Code, rr.Body.String())
		}
	}
	f.assertPassword(t, "alice", stepUpPassword, newPassword)

	// Setting someone else's password as their administrator is unchanged.
	bob := &gateonv1.User{Username: "bob", Password: "bobs-pass", Role: auth.RoleViewer}
	if err := f.m.UpsertUser(bob); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	body := `{"id":"` + bob.Id + `","username":"bob","role":"viewer","password":"` + newPassword + `"}`
	if rr := f.as(t, http.MethodPut, "/v1/users", body); rr.Code != http.StatusOK {
		t.Fatalf("editing bob: status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	f.assertPassword(t, "bob", newPassword, "bobs-pass")
}
