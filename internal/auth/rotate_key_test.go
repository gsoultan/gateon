// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

const rotatedKey = "fedcba9876543210fedcba9876543210"

// TestUpdateSymmetricKeyKeepsEverySecondFactor: stored second factors are
// encrypted under the session key. A rotation used to swap the key and leave
// them behind, so every 2FA account -- the administrator who rotated included
// -- could no longer complete a sign-in.
func TestUpdateSymmetricKeyKeepsEverySecondFactor(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "alice", "correct-horse-battery")
	secret, _ := enroll(t, m, id, "correct-horse-battery")

	if err := m.UpdateSymmetricKey(rotatedKey); err != nil {
		t.Fatalf("UpdateSymmetricKey: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ok, token, _, err := m.Verify2FA(challengeFor(t, m, id), id, code)
	if err != nil || !ok || token == "" {
		t.Fatalf("after a key rotation the enrolled second factor no longer verifies: ok=%v err=%v", ok, err)
	}
}

// TestUpdateSymmetricKeyEndsEverySession: that is what rotating the key is for.
func TestUpdateSymmetricKeyEndsEverySession(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "bob", "correct-horse-battery")
	old, _, err := m.Authenticate("bob", "correct-horse-battery", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSymmetricKey(rotatedKey); err != nil {
		t.Fatalf("UpdateSymmetricKey: %v", err)
	}
	if _, err := m.VerifyToken(old); err == nil {
		t.Fatal("a session signed with the previous key still verifies")
	}
	fresh, _, err := m.Authenticate("bob", "correct-horse-battery", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyToken(fresh); err != nil {
		t.Fatalf("a session signed with the new key does not verify: %v", err)
	}
}

// TestUpdateSymmetricKeyRefusesAShortKey instead of ignoring it without a
// word, and keeps the key in force.
func TestUpdateSymmetricKeyRefusesAShortKey(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "carol", "correct-horse-battery")
	token, _, err := m.Authenticate("carol", "correct-horse-battery", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateSymmetricKey("too-short"); !errors.Is(err, ErrSessionKeyTooShort) {
		t.Fatalf("UpdateSymmetricKey(short) = %v; want ErrSessionKeyTooShort", err)
	}
	if _, err := m.VerifyToken(token); err != nil {
		t.Fatalf("a refused key ended the session: %v", err)
	}
}
