// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// storedTOTPSecret reads the account's stored (encrypted) TOTP secret.
func storedTOTPSecret(t *testing.T, m *Manager, id string) string {
	t.Helper()
	var stored string
	q := m.dialect.Rebind("SELECT two_factor_secret FROM users WHERE id = ?")
	if err := m.db.QueryRow(q, id).Scan(&stored); err != nil {
		t.Fatalf("query stored secret: %v", err)
	}
	return stored
}

// TestSetup2FARefusesAWrongPassword: self-service setup needed only the
// account id, so a session -- which script in the dashboard can ride without
// reading -- was enough to be handed a TOTP secret for the account. A wrong
// password must be refused before anything is generated or stored.
func TestSetup2FARefusesAWrongPassword(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "grace", "right-passphrase")

	e, err := m.Setup2FA(id, "wrong-pass")
	secret, qr, codes := e.Secret, e.QRCodeURL, e.RecoveryCodes
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if secret != "" || qr != "" || len(codes) != 0 {
		t.Fatalf("refused setup disclosed enrolment material: secret=%q qr=%d bytes codes=%d", secret, len(qr), len(codes))
	}
	if stored := storedTOTPSecret(t, m, id); stored != "" {
		t.Fatalf("refused setup stored a TOTP secret: %q", stored)
	}
}

// TestSetup2FAWrongPasswordsLockTheStepUp: the step-up is a first-factor
// check, so it must not be a way to guess the password without a lockout. It
// locks the step-up -- reached only with the account's session -- and not the
// sign-in: a session in hostile hands (script in the dashboard) must not be
// able to lock the owner out of signing in (ADR 0050).
func TestSetup2FAWrongPasswordsLockTheStepUp(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "heidi", "right-passphrase")

	for i := range MaxFailedAttempts {
		if _, err := m.Setup2FA(id, "wrong-pass"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	if _, err := m.Setup2FA(id, "right-passphrase"); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("step-up with the right password on a locked account: err = %v, want ErrAccountLocked", err)
	}
	if _, _, err := m.Authenticate("heidi", "right-passphrase", "198.51.100.7"); err != nil {
		t.Errorf("sign-in after %d wrong step-up passwords: err = %v, want a session", MaxFailedAttempts, err)
	}
}

// TestSignInGuessesDoNotLockTheStepUp: the step-up's count is its own, so a
// stranger guessing at the sign-in form -- who has no session and cannot reach
// the step-up -- does not lock the owner out of it. The two used to share one
// count, which is what let anyone lock the owner out of everything (ADR 0050).
func TestSignInGuessesDoNotLockTheStepUp(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "ivan", "right-passphrase")

	for range MaxFailedAttempts {
		if _, _, err := m.Authenticate("ivan", "wrong-pass", "203.0.113.9"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong sign-in: err = %v", err)
		}
	}
	if _, err := m.Setup2FA(id, "right-passphrase"); err != nil {
		t.Errorf("step-up after a stranger's %d wrong sign-ins: err = %v, want success", MaxFailedAttempts, err)
	}
}

// TestSetup2FAWithThePasswordClearsTheFailureCount pins the other half of
// "like sign-in": a correct password resets the count, as a sign-in does.
func TestSetup2FAWithThePasswordClearsTheFailureCount(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "judy", "right-passphrase")

	for range MaxFailedAttempts - 1 {
		_, _ = m.Setup2FA(id, "wrong-pass")
	}
	if _, err := m.Setup2FA(id, "right-passphrase"); err != nil {
		t.Fatalf("step-up with the right password: %v", err)
	}
	for range MaxFailedAttempts - 1 {
		_, _ = m.Setup2FA(id, "wrong-pass")
	}
	if _, err := m.Setup2FA(id, "right-passphrase"); err != nil {
		t.Errorf("the count was not cleared by the correct password: %v", err)
	}
}

// TestSetup2FAOnADisabledAccount follows sign-in: disabled is only revealed
// after a correct password, so the prompt cannot enumerate disabled accounts.
func TestSetup2FAOnADisabledAccount(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "ken", "right-passphrase")
	if err := m.SetUserDisabled(id, true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	if _, err := m.Setup2FA(id, "wrong-pass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password on a disabled account: err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := m.Setup2FA(id, "right-passphrase"); !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("right password on a disabled account: err = %v, want ErrAccountDisabled", err)
	}
}

// TestRefusedSetup2FALeavesAnEnrolledAccountsFactorAlone: setup rewrites the
// stored secret and switches 2FA off until the new one is verified, so a setup
// that was let through replaced the owner's authenticator. A refused one must
// leave the enrolled factor exactly as it was.
func TestRefusedSetup2FALeavesAnEnrolledAccountsFactorAlone(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "leo", "right-passphrase")
	secret, _ := enroll(t, m, id, "right-passphrase")
	before := storedTOTPSecret(t, m, id)

	if _, err := m.Setup2FA(id, "wrong-pass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
	if after := storedTOTPSecret(t, m, id); after != before {
		t.Fatal("a refused setup replaced the enrolled TOTP secret")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, code); !ok || err != nil {
		t.Fatalf("the owner's authenticator no longer verifies: ok=%v err=%v", ok, err)
	}
	if _, _, err := m.Authenticate("leo", "right-passphrase", ""); !errors.Is(err, ErrTwoFactorRequired) {
		t.Errorf("sign-in no longer asks for the second factor: err = %v", err)
	}
}
