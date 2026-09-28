// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/pquerna/otp/totp"
)

// A session key changed without the dashboard's rotation -- global.json edited,
// the reference it names rotated at the source, a cluster node restarted with
// its peers' new key -- left every stored second factor encrypted under the old
// key: each 2FA account could no longer complete a sign-in, and nothing said
// why. These start a manager on a database whose second factors were written
// under another key, as a gateway restarted with a changed key does.

// managerWithKey opens a manager on dbPath with key, closed at the end of the test.
func managerWithKey(t *testing.T, dbPath, key string) *Manager {
	t.Helper()
	m, err := NewManager(dbPath, key, logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// enrolledUnderOldKey enrolls a user under testSymmetricKey and returns the
// database, the user and the TOTP secret, with that manager closed.
func enrolledUnderOldKey(t *testing.T) (dbPath, id, secret string) {
	t.Helper()
	dbPath = filepath.Join(t.TempDir(), "auth.db")
	old, err := NewManager(dbPath, testSymmetricKey, logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	id = createUser(t, old, "carol", "correct-horse-battery")
	secret, _ = enroll(t, old, id, "correct-horse-battery")
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	return dbPath, id, secret
}

func signInWithSecondFactor(t *testing.T, m *Manager, id, secret string) error {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ok, token, _, err := m.Verify2FA(id, code)
	if err != nil {
		return err
	}
	if !ok || token == "" {
		return errors.New("the second factor did not verify")
	}
	return nil
}

func storedSecondFactor(t *testing.T, m *Manager, id string) string {
	t.Helper()
	var stored string
	if err := m.db.QueryRow("SELECT two_factor_secret FROM users WHERE id = ?", id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestReconcileMovesSecondFactorsFromThePreviousKey(t *testing.T) {
	dbPath, id, secret := enrolledUnderOldKey(t)
	m := managerWithKey(t, dbPath, rotatedKey)
	if err := signInWithSecondFactor(t, m, id, secret); err == nil {
		t.Fatal("precondition: a second factor written under another key verified under the new one")
	}

	report, err := m.ReconcileSecondFactors(testSymmetricKey)
	if err != nil {
		t.Fatalf("ReconcileSecondFactors: %v", err)
	}
	if report.Moved != 1 || report.Unreadable != 0 {
		t.Fatalf("report = %+v, want the one second factor moved", report)
	}
	if err := signInWithSecondFactor(t, m, id, secret); err != nil {
		t.Fatalf("after moving it from the previous key the second factor still does not verify: %v", err)
	}
}

func TestReconcileWithoutThePreviousKeyCountsTheLockedOutAccounts(t *testing.T) {
	dbPath, id, secret := enrolledUnderOldKey(t)
	m := managerWithKey(t, dbPath, rotatedKey)
	before := storedSecondFactor(t, m, id)

	report, err := m.ReconcileSecondFactors("")
	if err != nil {
		t.Fatalf("ReconcileSecondFactors: %v", err)
	}
	if report.Unreadable != 1 || report.Moved != 0 {
		t.Fatalf("report = %+v, want the one second factor counted as unreadable", report)
	}
	// Left as it was, so the previous key can still recover it later.
	if after := storedSecondFactor(t, m, id); after != before {
		t.Fatal("an unreadable second factor was rewritten; the previous key could no longer recover it")
	}
	if _, err := m.ReconcileSecondFactors(testSymmetricKey); err != nil {
		t.Fatal(err)
	}
	if err := signInWithSecondFactor(t, m, id, secret); err != nil {
		t.Fatalf("the previous key, given later, did not recover the second factor: %v", err)
	}
}

// Every node of a cluster runs the pass at startup; only the first may move
// anything.
func TestReconcileLeavesSecondFactorsUnderTheKeyInForceAlone(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "dave", "correct-horse-battery")
	enroll(t, m, id, "correct-horse-battery")
	before := storedSecondFactor(t, m, id)

	report, err := m.ReconcileSecondFactors(rotatedKey)
	if err != nil {
		t.Fatalf("ReconcileSecondFactors: %v", err)
	}
	if report != (SecondFactorKeyReport{}) {
		t.Fatalf("report = %+v, want nothing moved and nothing unreadable", report)
	}
	if after := storedSecondFactor(t, m, id); after != before {
		t.Fatal("a second factor already under the key in force was rewritten")
	}
}

// The previous key is for moving second factors, and nothing else: a key that
// was rotated away must not sign anyone in.
func TestThePreviousKeyNeverVerifiesASession(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	old := managerWithKey(t, dbPath, testSymmetricKey)
	createUser(t, old, "erin", "correct-horse-battery")
	token, _, err := old.Authenticate("erin", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}

	m := managerWithKey(t, dbPath, rotatedKey)
	if _, err := m.ReconcileSecondFactors(testSymmetricKey); err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyToken(token); err == nil {
		t.Fatal("a session signed with the previous key verified once that key was given to move second factors")
	}
}

func TestReconcileRefusesAShortPreviousKey(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.ReconcileSecondFactors("too-short"); !errors.Is(err, ErrSessionKeyTooShort) {
		t.Fatalf("err = %v, want ErrSessionKeyTooShort", err)
	}
}

// A second factor stored before encryption at rest is plaintext; the pass
// encrypts it under the key in force, as a rotation always has.
func TestReconcileEncryptsAPlaintextSecondFactor(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "frank", "correct-horse-battery")
	secret, _ := enroll(t, m, id, "correct-horse-battery")
	if _, err := m.db.Exec("UPDATE users SET two_factor_secret = ? WHERE id = ?", secret, id); err != nil {
		t.Fatal(err)
	}

	report, err := m.ReconcileSecondFactors("")
	if err != nil {
		t.Fatalf("ReconcileSecondFactors: %v", err)
	}
	if report.Moved != 1 {
		t.Fatalf("report = %+v, want the plaintext second factor encrypted", report)
	}
	if stored := storedSecondFactor(t, m, id); !strings.HasPrefix(stored, encPrefix) {
		t.Fatalf("the second factor is still stored in plaintext: %q", stored)
	}
	if err := signInWithSecondFactor(t, m, id, secret); err != nil {
		t.Fatalf("the encrypted second factor does not verify: %v", err)
	}
}
