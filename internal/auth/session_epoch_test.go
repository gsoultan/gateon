// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
)

// legacyHash stands in for a password hash in the users table. The digests
// pinned beside it below are what the release before the session epoch put in
// the "sb" claim for it, captured by running that release's derivation.
const legacyHash = "$2a$10$legacy-hash-for-golden-test"

// TestAnAccountThatNeverSignedOutKeepsItsPreUpgradeBinding: the previous
// release bound tokens to digest(password hash, role, disabled). While an
// account's epoch is zero -- every account, straight after the migration --
// the digest must be that one, byte for byte. Otherwise replacing the binary
// signs out every administrator mid-session and breaks every API client
// holding a token.
func TestAnAccountThatNeverSignedOutKeepsItsPreUpgradeBinding(t *testing.T) {
	for _, c := range []struct {
		state accountState
		want  string
	}{
		{accountState{passwordHash: legacyHash, role: RoleAdmin}, "ca100404af562ff4180cc78217efd701"},
		{accountState{passwordHash: legacyHash, role: RoleViewer, disabled: true}, "9adc3d8902d1782dd20731b2b060fb56"},
	} {
		if got := c.state.binding(); got != c.want {
			t.Errorf("role %s, disabled %v: binding %s, want the pre-upgrade %s",
				c.state.role, c.state.disabled, got, c.want)
		}
	}
}

// TestATokenIssuedBeforeTheUpgradeStillVerifies presents a token minted the
// way the previous release minted it to an account the migration has just
// given epoch 0 -- and then checks the upgrade did not make it immune to
// signing out.
func TestATokenIssuedBeforeTheUpgradeStillVerifies(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		username := e.name("legacy")
		id := e.create(t, username, "any-password", RoleAdmin)
		// The row as the previous release left it: the hash its token was
		// bound to, and the epoch the migration gives every row.
		q := e.m.Dialect().Rebind("UPDATE users SET password = ? WHERE id = ?")
		if _, err := e.m.DB().Exec(q, legacyHash, id); err != nil {
			t.Fatalf("setting the legacy hash: %v", err)
		}
		e.m.InvalidateBinding(id) // the UPDATE went round the manager

		token := legacyToken(e.m, id, username, "ca100404af562ff4180cc78217efd701")
		if _, err := e.m.VerifyToken(token); err != nil {
			t.Fatalf("a session issued before the upgrade was refused after it: %v", err)
		}
		if err := e.m.EndSessions(id); err != nil {
			t.Fatalf("EndSessions: %v", err)
		}
		if _, err := e.m.VerifyToken(token); !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("the pre-upgrade session after signing out: err %v, want ErrSessionRevoked", err)
		}
	})
}

// legacyToken mints an administrator session for id the way issueToken did
// before the session epoch existed, with binding as its "sb" claim.
func legacyToken(m *Manager, id, username, binding string) string {
	token := paseto.NewToken()
	now := time.Now()
	token.SetExpiration(now.Add(TokenLifetime))
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetSubject(id)
	token.SetString("id", id)
	token.SetString("username", username)
	token.SetString("role", RoleAdmin)
	token.SetString(SessionBindingClaim, binding)
	return token.V4Encrypt(m.symmetricKey, nil)
}

// TestSigningOutEndsEverySessionOfTheAccount is the regression test for a
// sign-out that ended nothing.
//
// Root cause: sign-out cleared the cookie and wrote an audit entry, and changed
// none of the session binding's inputs, so the bearer token the cookie held --
// and every copy of it -- went on verifying until it expired, up to
// TokenLifetime later.
func TestSigningOutEndsEverySessionOfTheAccount(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		alice, bob := e.name("alice"), e.name("bob")
		aliceID := e.create(t, alice, "alice-password", RoleAdmin)
		e.create(t, bob, "bob-password", RoleViewer)
		laptop, phone := e.signIn(t, alice, "alice-password"), e.signIn(t, alice, "alice-password")
		bobs := e.signIn(t, bob, "bob-password")

		if err := e.m.EndSessions(aliceID); err != nil {
			t.Fatalf("EndSessions: %v", err)
		}

		for name, token := range map[string]string{
			"the session that signed out":    laptop,
			"another session of the account": phone,
		} {
			if _, err := e.m.VerifyToken(token); !errors.Is(err, ErrSessionRevoked) {
				t.Errorf("%s: err %v after signing out, want ErrSessionRevoked", name, err)
			}
		}
		if _, err := e.m.VerifyToken(bobs); err != nil {
			t.Errorf("another account's session ended too: %v", err)
		}
		// Signed out is not locked out.
		if _, err := e.m.VerifyToken(e.signIn(t, alice, "alice-password")); err != nil {
			t.Errorf("a session issued after signing out was refused: %v", err)
		}
	})
}

// TestASecondSignOutIsHarmless: signing out twice -- a double click, two
// tabs, a retry -- must not fail and must not leave the account unable to sign
// in; nor may signing out an account that no longer exists.
func TestASecondSignOutIsHarmless(t *testing.T) {
	onEveryEngine(t, func(t *testing.T, e engineManager) {
		carol := e.name("carol")
		id := e.create(t, carol, "carol-password", RoleOperator)
		e.signIn(t, carol, "carol-password")
		for i := 1; i <= 2; i++ {
			if err := e.m.EndSessions(id); err != nil {
				t.Fatalf("sign-out %d: %v", i, err)
			}
		}
		if _, err := e.m.VerifyToken(e.signIn(t, carol, "carol-password")); err != nil {
			t.Errorf("after two sign-outs a new session is refused: %v", err)
		}
		if err := e.m.EndSessions("no-such-account"); err != nil {
			t.Errorf("signing out an account that does not exist: %v", err)
		}
	})
}

// TestAnEmptyHolderDoesNotReportASignOut: before Setup there is no manager to
// end anything with, and success would tell the caller its sessions ended.
func TestAnEmptyHolderDoesNotReportASignOut(t *testing.T) {
	if err := NewHolder(nil).EndSessions("user-1"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("EndSessions on an empty Holder: err %v, want ErrUnavailable", err)
	}
}
