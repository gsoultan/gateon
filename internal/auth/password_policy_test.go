// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"

	"github.com/gsoultan/gateon/internal/auth/passpolicy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestUserCreateRefusesAWeakPassword is M11 at account creation: "a" was
// accepted, and "" stored an empty hash.
func TestUserCreateRefusesAWeakPassword(t *testing.T) {
	m := newTestManager(t)
	for _, p := range []string{"a", "", "password1234"} {
		u := &gateonv1.User{Username: "weak", Password: p, Role: RoleViewer}
		if err := m.UpsertUser(u); !errors.Is(err, passpolicy.ErrWeak) {
			t.Errorf("create with password %q: err = %v, want a policy refusal", p, err)
		}
	}
	if users, _, _ := m.ListUsers(0, 10, "weak"); len(users) != 0 {
		t.Errorf("a refused create left %d accounts behind", len(users))
	}
}

// TestUserEditKeepsThePasswordWhenNoneIsGiven: the policy must not stop an
// administrator renaming or re-roling an account without retyping its
// password.
func TestUserEditKeepsThePasswordWhenNoneIsGiven(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "carol", "her-own-passphrase")
	if err := m.UpsertUser(&gateonv1.User{Id: id, Username: "carol", Role: RoleViewer}); err != nil {
		t.Fatalf("edit without a password: %v", err)
	}
	if _, _, err := m.Authenticate("carol", "her-own-passphrase", ""); err != nil {
		t.Errorf("the password did not survive an edit that gave none: %v", err)
	}
	if err := m.UpsertUser(&gateonv1.User{Id: id, Username: "carol", Password: "short", Role: RoleViewer}); !errors.Is(err, passpolicy.ErrWeak) {
		t.Errorf("edit with a weak password: err = %v, want a policy refusal", err)
	}
}

// TestPasswordChangeRefusesAWeakPassword is M11 at a password change, by an
// administrator and by the owner.
func TestPasswordChangeRefusesAWeakPassword(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "carol", "her-own-passphrase")
	if err := m.ChangePassword(id, "a"); !errors.Is(err, passpolicy.ErrWeak) {
		t.Errorf("ChangePassword to %q: err = %v, want a policy refusal", "a", err)
	}
	if err := m.ChangePassword(id, "carol-in-the-garden"); !errors.Is(err, passpolicy.ErrUsername) {
		t.Errorf("ChangePassword to one containing the username: err = %v, want ErrUsername", err)
	}
	if err := m.ChangeOwnPassword(id, "her-own-passphrase", "a"); !errors.Is(err, passpolicy.ErrWeak) {
		t.Errorf("ChangeOwnPassword to %q: err = %v, want a policy refusal", "a", err)
	}
	if _, _, err := m.Authenticate("carol", "her-own-passphrase", ""); err != nil {
		t.Errorf("a refused change replaced the password: %v", err)
	}
}

// TestAWeakNewPasswordDoesNotSpendAGuess: the owner's change is checked
// against the policy before the current password is, so a refused new one
// does not count towards the lock on the current one.
func TestAWeakNewPasswordDoesNotSpendAGuess(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "carol", "her-own-passphrase")
	for range MaxFailedAttempts + 1 {
		if err := m.ChangeOwnPassword(id, "a-wrong-current", "weak"); !errors.Is(err, passpolicy.ErrWeak) {
			t.Fatalf("err = %v, want a policy refusal", err)
		}
	}
	if err := m.ChangeOwnPassword(id, "her-own-passphrase", "her-new-passphrase"); err != nil {
		t.Errorf("after refused weak changes the owner's change failed: %v", err)
	}
}
