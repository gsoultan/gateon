// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// TestResetTwoFactorRemovesTheFactorAndEndsTheSessions is MGMT-N5 (ADR 0057):
// there was no way for an administrator to reset another account's second
// factor, so an account whose authenticator was lost could only be deleted.
// The reset removes the factor, requires a new enrolment at the next sign-in
// -- the account is not left password-only -- and ends every session, which
// may be the session of whoever holds the lost device.
func TestResetTwoFactorRemovesTheFactorAndEndsTheSessions(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		const password = "reset-me-passphrase"
		name := e.name("lost-device")
		id := e.create(t, name, password, RoleOperator)
		secret, _ := enroll(t, e.m, id, password)
		session := e.signInWithBothFactors(t, name, password, id, secret)

		if err := e.m.ResetTwoFactor(id); err != nil {
			t.Fatalf("ResetTwoFactor: %v", err)
		}

		if _, err := e.m.VerifyToken(session); err == nil {
			t.Error("a session issued before the reset still verifies; the reset must end it")
		}
		if got := storedTOTPSecret(t, e.m, id); got != "" {
			t.Errorf("the TOTP secret is still stored after the reset (%d bytes)", len(got))
		}
		users, _, err := e.m.ListUsers(0, 10, name)
		if err != nil || len(users) != 1 {
			t.Fatalf("ListUsers(%q) = %v, %v", name, users, err)
		}
		if users[0].GetTwoFactorEnabled() || !users[0].GetTwoFactorPending() {
			t.Errorf("after the reset enabled=%v pending=%v; want a new enrolment required",
				users[0].GetTwoFactorEnabled(), users[0].GetTwoFactorPending())
		}
		if _, _, err := e.m.Authenticate(name, password, ""); !errors.Is(err, ErrTwoFactorSetupRequired) {
			t.Errorf("sign-in after the reset = %v; want %v (enrol a new authenticator)", err, ErrTwoFactorSetupRequired)
		}
	})
}

// TestResetTwoFactorOfNoAccountIsNotFound: a reset that changed nothing must
// not answer success, or the dashboard would say an account was reset.
func TestResetTwoFactorOfNoAccountIsNotFound(t *testing.T) {
	m := newTestManager(t)
	if err := m.ResetTwoFactor("no-such-account"); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("ResetTwoFactor of an unknown id = %v; want %v", err, ErrNoSuchUser)
	}
}

// signInWithBothFactors signs an enrolled account in through both factors and
// returns the session.
func (e engineManager) signInWithBothFactors(t *testing.T, name, password, id, secret string) string {
	t.Helper()
	_, _, err := e.m.Authenticate(name, password, "")
	var step *SecondStepError
	if !errors.As(err, &step) {
		t.Fatalf("sign-in of an enrolled account = %v; want the second step", err)
	}
	// The next period's code: enroll spent this period's, and a code is
	// accepted once.
	code, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	ok, token, _, err := e.m.Verify2FA(step.Challenge, id, code)
	if err != nil || !ok || token == "" {
		t.Fatalf("second step: ok=%v token=%q err=%v", ok, token, err)
	}
	if _, err := e.m.VerifyToken(token); err != nil {
		t.Fatalf("the session does not verify before the reset: %v", err)
	}
	return token
}
