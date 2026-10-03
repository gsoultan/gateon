// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"
)

// TestChangeOwnPasswordNeedsTheCurrentPassword: the self-service change is the
// sign-in's first-factor check followed by the change, so a wrong current
// password changes nothing and counts like a failed sign-in.
func TestChangeOwnPasswordNeedsTheCurrentPassword(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "mia", "old-passphrase")

	if err := m.ChangeOwnPassword(id, "wrong-pass", "new-passphrase"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password: err = %v, want ErrInvalidCredentials", err)
	}
	if _, _, err := m.Authenticate("mia", "old-passphrase", ""); err != nil {
		t.Fatalf("a refused change changed the password: %v", err)
	}

	for range MaxFailedAttempts {
		_ = m.ChangeOwnPassword(id, "wrong-pass", "new-passphrase")
	}
	if err := m.ChangeOwnPassword(id, "old-passphrase", "new-passphrase"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("after the lockout limit: err = %v, want ErrAccountLocked", err)
	}
}

// TestChangeOwnPasswordWithTheCurrentPassword pins the working path.
func TestChangeOwnPasswordWithTheCurrentPassword(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "noah", "old-passphrase")

	if err := m.ChangeOwnPassword(id, "old-passphrase", "new-passphrase"); err != nil {
		t.Fatalf("ChangeOwnPassword: %v", err)
	}
	if _, _, err := m.Authenticate("noah", "new-passphrase", ""); err != nil {
		t.Errorf("the new password does not sign in: %v", err)
	}
	if _, _, err := m.Authenticate("noah", "old-passphrase", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password still signs in: %v", err)
	}
}
