// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

// A session issued by a 2FA sign-in must carry the account's role, exactly as a
// password-only sign-in does. Verify2FA read the role into a local variable and
// issued the token from a User whose Role was never set, so every account with
// 2FA -- administrators included -- signed in to a session with role "" and was
// refused by every permission check. Fail-closed, but it locked out precisely
// the accounts that followed the advice to enrol.
func TestVerify2FASessionCarriesTheAccountRole(t *testing.T) {
	for _, role := range []string{RoleAdmin, RoleOperator} {
		t.Run(role, func(t *testing.T) {
			m := newTestManager(t)
			u := &gateonv1.User{Username: "u-" + role, Password: "correct-horse-battery", Role: role}
			if err := m.UpsertUser(u); err != nil {
				t.Fatalf("UpsertUser: %v", err)
			}
			secret, codes := enroll(t, m, u.Id, "correct-horse-battery")

			// The next TOTP window, so the code differs from the one enroll used.
			code, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			assertSessionRole(t, m, u.Id, code, role, "a TOTP code")
			assertSessionRole(t, m, u.Id, codes[0], role, "a recovery code")
		})
	}
}

func assertSessionRole(t *testing.T, m *Manager, id, code, want, via string) {
	t.Helper()
	ok, token, user, err := m.Verify2FA(id, code)
	if err != nil || !ok {
		t.Fatalf("Verify2FA with %s: ok=%v err=%v", via, ok, err)
	}
	v, err := m.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	claims, isClaims := v.(*Claims)
	if !isClaims {
		t.Fatalf("VerifyToken returned %T, want *Claims", v)
	}
	if claims.Role != want {
		t.Errorf("a 2FA sign-in with %s issued a session with role %q; want %q", via, claims.Role, want)
	}
	if user.GetRole() != want {
		t.Errorf("a 2FA sign-in with %s answered with user role %q; want %q", via, user.GetRole(), want)
	}
}

// A disabled account must not sign in through the second step either. Login
// refuses a disabled account after its password, but Verify2FA is reachable on
// its own with an account id and a code, and it never looked at Disabled -- so
// disabling a user who still held their authenticator or a recovery code did
// not stop them signing in.
func TestVerify2FARefusesADisabledAccount(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "leaver", "correct-horse-battery")
	secret, codes := enroll(t, m, id, "correct-horse-battery")

	if err := m.SetUserDisabled(id, true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for via, c := range map[string]string{"a TOTP code": code, "a recovery code": codes[0]} {
		ok, token, _, err := m.Verify2FA(id, c)
		if ok || token != "" {
			t.Errorf("a disabled account signed in with %s (ok=%v, token issued=%v, err=%v)", via, ok, token != "", err)
		}
	}
}

// The binding layer refuses a disabled account on its own, whichever path asks
// for a session: issuing one fails, so no future sign-in step can mint a token
// that matches a disabled account's binding.
func TestNoSessionIsIssuedForADisabledAccount(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "leaver", "correct-horse-battery")
	if err := m.SetUserDisabled(id, true); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	token, _, err := m.issueToken(&gateonv1.User{Id: id, Username: "leaver", Role: RoleAdmin, Disabled: true})
	if err == nil || token != "" {
		t.Fatalf("a session was issued for a disabled account (err=%v)", err)
	}
}
