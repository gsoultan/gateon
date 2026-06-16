package auth

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

const testSymmetricKey = "0123456789abcdef0123456789abcdef"

// newTestManager spins up a Manager backed by a throwaway SQLite database.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "auth_test.db")
	m, err := NewManager(dbPath, testSymmetricKey, logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// createUser inserts a user with a known password and returns its id.
func createUser(t *testing.T, m *Manager, username, password string) string {
	t.Helper()
	u := &gateonv1.User{Username: username, Password: password, Role: RoleAdmin}
	if err := m.UpsertUser(u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	return u.Id
}

// enroll runs Setup2FA followed by a TOTP verification to fully enable 2FA.
// It returns the plaintext secret and recovery codes.
func enroll(t *testing.T, m *Manager, id string) (secret string, codes []string) {
	t.Helper()
	secret, _, codes, err := m.Setup2FA(id)
	if err != nil {
		t.Fatalf("Setup2FA: %v", err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	ok, token, _, err := m.Verify2FA(id, code)
	if err != nil {
		t.Fatalf("Verify2FA(enable): %v", err)
	}
	if !ok || token == "" {
		t.Fatalf("Verify2FA(enable): expected success with token, got ok=%v token=%q", ok, token)
	}
	return secret, codes
}

func TestAuthenticateDoesNotLeakSecretWhen2FARequired(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "alice", "s3cret-pass")
	enroll(t, m, id)

	token, user, err := m.Authenticate("alice", "s3cret-pass")
	if !errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("expected ErrTwoFactorRequired, got %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token on 2FA challenge, got %q", token)
	}
	if user == nil {
		t.Fatal("expected user on 2FA challenge")
	}
	if user.TwoFactorSecret != "" {
		t.Fatalf("TOTP secret leaked to client: %q", user.TwoFactorSecret)
	}
	if user.Password != "" {
		t.Fatalf("password leaked to client: %q", user.Password)
	}
	if len(user.RecoveryCodes) != 0 {
		t.Fatalf("recovery codes leaked to client: %v", user.RecoveryCodes)
	}
}

func TestSetup2FAStoresEncryptedSecret(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "carol", "pw")
	secret, _, _, err := m.Setup2FA(id)
	if err != nil {
		t.Fatalf("Setup2FA: %v", err)
	}

	var stored string
	q := m.dialect.Rebind("SELECT two_factor_secret FROM users WHERE id = ?")
	if err := m.db.QueryRow(q, id).Scan(&stored); err != nil {
		t.Fatalf("query stored secret: %v", err)
	}
	if stored == secret {
		t.Fatal("secret stored in plaintext")
	}
	dec, err := decryptSecret(m.encKey, stored)
	if err != nil {
		t.Fatalf("decryptSecret: %v", err)
	}
	if dec != secret {
		t.Fatalf("decrypted secret mismatch: got %q want %q", dec, secret)
	}
}

func TestVerify2FARecoveryCodeOnlyAfterEnabled(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "dave", "pw")
	// Setup but do NOT enable.
	_, _, codes, err := m.Setup2FA(id)
	if err != nil {
		t.Fatalf("Setup2FA: %v", err)
	}

	ok, _, _, err := m.Verify2FA(id, codes[0])
	if ok {
		t.Fatal("recovery code must not be accepted before 2FA is enabled")
	}
	if !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Fatalf("expected ErrInvalidTwoFactorCode, got %v", err)
	}
}

func TestVerify2FARecoveryCodeConsumed(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "erin", "pw")
	_, codes := enroll(t, m, id)

	// First use of a recovery code succeeds.
	ok, token, _, err := m.Verify2FA(id, codes[0])
	if err != nil || !ok || token == "" {
		t.Fatalf("recovery login failed: ok=%v token=%q err=%v", ok, token, err)
	}

	// The same recovery code must not work twice.
	ok, _, _, err = m.Verify2FA(id, codes[0])
	if ok {
		t.Fatal("recovery code was accepted twice")
	}
	if !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Fatalf("expected ErrInvalidTwoFactorCode on reused code, got %v", err)
	}
}

func TestVerify2FALockoutAfterRepeatedFailures(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "frank", "pw")
	enroll(t, m, id)

	var lastErr error
	for range MaxFailedAttempts {
		_, _, _, lastErr = m.Verify2FA(id, "000000")
	}
	if !errors.Is(lastErr, ErrInvalidTwoFactorCode) {
		t.Fatalf("expected ErrInvalidTwoFactorCode during failures, got %v", lastErr)
	}

	// The account should now be locked.
	if _, _, _, err := m.Verify2FA(id, "000000"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked after %d failures, got %v", MaxFailedAttempts, err)
	}
}
