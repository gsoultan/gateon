package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestAuthenticateRejectsDisabledAccount(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "mallory", "pw-123456")

	// A normal login works before disabling.
	if _, _, err := m.Authenticate("mallory", "pw-123456"); err != nil {
		t.Fatalf("expected successful login before disable, got %v", err)
	}

	if err := m.SetUserDisabled(id, true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}

	// Correct password must still be rejected once disabled.
	token, _, err := m.Authenticate("mallory", "pw-123456")
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("expected ErrAccountDisabled, got %v", err)
	}
	if token != "" {
		t.Fatalf("expected no token for disabled account, got %q", token)
	}

	// Re-enabling restores access.
	if err := m.SetUserDisabled(id, false); err != nil {
		t.Fatalf("SetUserDisabled(false): %v", err)
	}
	if _, _, err := m.Authenticate("mallory", "pw-123456"); err != nil {
		t.Fatalf("expected login to succeed after re-enable, got %v", err)
	}
}

func TestAuthenticateSignalsPending2FASetup(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "nina", "pw-123456")

	if err := m.SetTwoFactorPending(id, true); err != nil {
		t.Fatalf("SetTwoFactorPending: %v", err)
	}

	token, user, err := m.Authenticate("nina", "pw-123456")
	if !errors.Is(err, ErrTwoFactorSetupRequired) {
		t.Fatalf("expected ErrTwoFactorSetupRequired, got %v", err)
	}
	if token != "" {
		t.Fatalf("expected no session token when enrollment is pending, got %q", token)
	}
	if user == nil || user.Id != id {
		t.Fatalf("expected the pending user to be returned for enrollment, got %+v", user)
	}
	// The challenge response must never carry credential material.
	if user.TwoFactorSecret != "" || user.Password != "" {
		t.Fatalf("credential material leaked on pending-2FA response: %+v", user)
	}
}

func TestEnrollPending2FACompletesAndClearsPending(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "oscar", "pw-123456")
	if err := m.SetTwoFactorPending(id, true); err != nil {
		t.Fatalf("SetTwoFactorPending: %v", err)
	}

	// Wrong password must not start enrollment (and must not leak a secret).
	if _, _, _, _, err := m.EnrollPending2FA("oscar", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for bad password, got %v", err)
	}

	secret, _, _, enrollID, err := m.EnrollPending2FA("oscar", "pw-123456")
	if err != nil {
		t.Fatalf("EnrollPending2FA: %v", err)
	}
	if enrollID != id {
		t.Fatalf("enroll returned id %q, want %q", enrollID, id)
	}
	if secret == "" {
		t.Fatal("expected a TOTP secret from enrollment")
	}

	// Completing verification enables 2FA and clears the pending flag.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	ok, token, _, err := m.Verify2FA(id, code)
	if err != nil || !ok || token == "" {
		t.Fatalf("Verify2FA(enroll): ok=%v token=%q err=%v", ok, token, err)
	}

	var enabled, pending bool
	q := m.dialect.Rebind("SELECT two_factor_enabled, two_factor_pending FROM users WHERE id = ?")
	if err := m.db.QueryRow(q, id).Scan(&enabled, &pending); err != nil {
		t.Fatalf("query 2FA state: %v", err)
	}
	if !enabled {
		t.Fatal("expected 2FA to be enabled after enrollment")
	}
	if pending {
		t.Fatal("expected two_factor_pending to be cleared after enrollment")
	}

	// Next login now takes the normal 2FA code-challenge path.
	if _, _, err := m.Authenticate("oscar", "pw-123456"); !errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("expected ErrTwoFactorRequired after enrollment, got %v", err)
	}
}

func TestEnrollPendingRejectedWhenNotPending(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "peggy", "pw-123456")

	// No pending flag set: the unauthenticated enroll path must refuse, so it
	// can't be abused to (re)generate a TOTP secret for an arbitrary account.
	if _, _, _, _, err := m.EnrollPending2FA("peggy", "pw-123456"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials when not pending, got %v", err)
	}
}
