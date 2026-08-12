// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func newRevocationTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager("sqlite::memory:", "test-secret-key-32-bytes-minimum!", logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// loginFixture creates a user and returns its id and a live session token.
func loginFixture(t *testing.T, m *Manager, username, password, role string) (id, token string) {
	t.Helper()
	u := &gateonv1.User{Username: username, Password: password, Role: role}
	if err := m.UpsertUser(u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	users, _, err := m.ListUsers(0, 100, username)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, cand := range users {
		if cand.Username == username {
			id = cand.Id
			break
		}
	}
	if id == "" {
		t.Fatalf("created user %q not found", username)
	}

	token, _, err = m.Authenticate(username, password)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if token == "" {
		t.Fatal("Authenticate returned an empty token")
	}

	if _, err := m.VerifyToken(token); err != nil {
		t.Fatalf("freshly issued token must verify, got %v", err)
	}
	return id, token
}

// TestSessionRevocation is the regression test for live sessions surviving
// account changes.
//
// Root cause: VerifyToken checked only the PASETO signature and the exp/nbf
// claims. Nothing on the request path read the users table, so disabling,
// deleting, demoting or re-passwording an account changed a row that no
// authenticated request ever consulted, and the token issued beforehand kept
// its original privileges until it expired on its own — up to a full day.
//
// Every subtest below passes against the unfixed manager, which is the bug.
func TestSessionRevocation(t *testing.T) {
	t.Run("disabling an account ends its live sessions", func(t *testing.T) {
		m := newRevocationTestManager(t)
		id, token := loginFixture(t, m, "alice", "correct-horse-battery", RoleAdmin)

		if err := m.SetUserDisabled(id, true); err != nil {
			t.Fatalf("SetUserDisabled: %v", err)
		}

		if _, err := m.VerifyToken(token); err == nil {
			t.Fatal("a disabled user's existing token still verifies — " +
				"disabling an account must take effect immediately, not at token expiry")
		} else if !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("want ErrSessionRevoked, got %v", err)
		}
	})

	t.Run("deleting an account ends its live sessions", func(t *testing.T) {
		m := newRevocationTestManager(t)
		id, token := loginFixture(t, m, "bob", "correct-horse-battery", RoleAdmin)

		if err := m.DeleteUser(id); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}

		if _, err := m.VerifyToken(token); err == nil {
			t.Fatal("a deleted user's token still verifies")
		}
	})

	t.Run("demotion ends sessions carrying the old role", func(t *testing.T) {
		m := newRevocationTestManager(t)
		id, token := loginFixture(t, m, "carol", "correct-horse-battery", RoleAdmin)

		// The role is baked into the token, so without revocation a demoted
		// administrator keeps administrator claims until the token expires.
		if err := m.UpsertUser(&gateonv1.User{Id: id, Username: "carol", Role: RoleViewer}); err != nil {
			t.Fatalf("UpsertUser (demote): %v", err)
		}

		claims, err := m.VerifyToken(token)
		if err == nil {
			if c, ok := claims.(*Claims); ok {
				t.Fatalf("a demoted user's token still verifies and still claims role %q", c.Role)
			}
			t.Fatal("a demoted user's token still verifies")
		}
		if !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("want ErrSessionRevoked, got %v", err)
		}
	})

	t.Run("password rotation ends sessions minted under the old password", func(t *testing.T) {
		m := newRevocationTestManager(t)
		id, token := loginFixture(t, m, "dave", "correct-horse-battery", RoleAdmin)

		if err := m.ChangePassword(id, "a-completely-different-password"); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}

		if _, err := m.VerifyToken(token); err == nil {
			t.Fatal("rotating a password left sessions minted under the old one alive")
		}
	})

	t.Run("unrelated accounts keep their sessions", func(t *testing.T) {
		m := newRevocationTestManager(t)
		aliceID, aliceToken := loginFixture(t, m, "alice", "correct-horse-battery", RoleAdmin)
		_, bobToken := loginFixture(t, m, "bob", "correct-horse-battery", RoleViewer)

		if err := m.SetUserDisabled(aliceID, true); err != nil {
			t.Fatalf("SetUserDisabled: %v", err)
		}

		if _, err := m.VerifyToken(aliceToken); err == nil {
			t.Error("alice's token should have been revoked")
		}
		if _, err := m.VerifyToken(bobToken); err != nil {
			t.Errorf("bob's unrelated session was revoked too: %v", err)
		}
	})

	t.Run("re-enabling issues a working session again", func(t *testing.T) {
		m := newRevocationTestManager(t)
		id, _ := loginFixture(t, m, "erin", "correct-horse-battery", RoleAdmin)

		if err := m.SetUserDisabled(id, true); err != nil {
			t.Fatalf("disable: %v", err)
		}
		if err := m.SetUserDisabled(id, false); err != nil {
			t.Fatalf("re-enable: %v", err)
		}

		token, _, err := m.Authenticate("erin", "correct-horse-battery")
		if err != nil {
			t.Fatalf("Authenticate after re-enable: %v", err)
		}
		if _, err := m.VerifyToken(token); err != nil {
			t.Errorf("a session issued after re-enabling must work, got %v", err)
		}
	})

	t.Run("a token with no binding is refused", func(t *testing.T) {
		// Tokens minted while the gateway was vulnerable carry no binding
		// claim. Accepting them would make the check optional for exactly the
		// population it exists to protect.
		m := newRevocationTestManager(t)
		id, _ := loginFixture(t, m, "frank", "correct-horse-battery", RoleAdmin)

		if err := m.checkSessionBinding(id, ""); !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("an empty binding must be refused, got %v", err)
		}
	})
}

// TestSessionBindingIsStableAndSensitive pins the derivation itself: stable for
// unchanged input (so tokens are not spuriously revoked on every verify) and
// different for each security-relevant field (so no change slips through).
func TestSessionBindingIsStableAndSensitive(t *testing.T) {
	base := sessionBinding("hash", RoleAdmin, false)

	if base != sessionBinding("hash", RoleAdmin, false) {
		t.Error("binding is not stable for identical input")
	}
	if base == sessionBinding("other-hash", RoleAdmin, false) {
		t.Error("password change did not change the binding")
	}
	if base == sessionBinding("hash", RoleViewer, false) {
		t.Error("role change did not change the binding")
	}
	if base == sessionBinding("hash", RoleAdmin, true) {
		t.Error("disabling did not change the binding")
	}
	// Length-prefixing guards the field boundaries.
	if sessionBinding("ab", "c", false) == sessionBinding("a", "bc", false) {
		t.Error("field boundaries collide; concatenation is ambiguous")
	}
	if base == "" {
		t.Error("binding must not be empty")
	}
}
