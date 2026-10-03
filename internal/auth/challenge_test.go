// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	mwauth "github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/pquerna/otp/totp"
)

// challengeFor is the challenge a correct password for id earns now: what
// Authenticate or Setup2FA would hand the caller. For tests whose subject is
// the code, not the step before it.
func challengeFor(t *testing.T, m *Manager, id string) string {
	t.Helper()
	c, err := m.issueChallenge(id, time.Now())
	if err != nil {
		t.Fatalf("issueChallenge: %v", err)
	}
	return c
}

// enrolledAccount is an account with 2FA on, and the TOTP code it would type now.
func enrolledAccount(t *testing.T, m *Manager, username string) (id, code string) {
	t.Helper()
	id = createUser(t, m, username, "correct-horse-battery")
	secret, _ := enroll(t, m, id, "correct-horse-battery")
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id, code
}

func assertRefusedChallenge(t *testing.T, m *Manager, challenge, id, code string) {
	t.Helper()
	ok, token, user, err := m.Verify2FA(challenge, id, code)
	if !errors.Is(err, ErrInvalidChallenge) {
		t.Errorf("err = %v, want ErrInvalidChallenge", err)
	}
	if ok || token != "" || user != nil {
		t.Errorf("refused step answered ok=%v token=%q user=%v", ok, token, user)
	}
}

func TestVerify2FARefusesAMissingChallenge(t *testing.T) {
	m := newTestManager(t)
	id, code := enrolledAccount(t, m, "alice")
	assertRefusedChallenge(t, m, "", id, code)
}

func TestVerify2FARefusesAnotherAccountsChallenge(t *testing.T) {
	m := newTestManager(t)
	id, code := enrolledAccount(t, m, "alice")
	bob := createUser(t, m, "bob", "the-other-accounts-pw")
	assertRefusedChallenge(t, m, challengeFor(t, m, bob), id, code)
}

// TestVerify2FARefusesAnotherAccountsChallengeWithTheSameBinding: the binding
// is a digest of account state, not of the account, so two accounts can share
// one -- here two with the same stored hash and the same role. UpsertUser no
// longer creates an account with no password (ADR 0050), and two hashes of one
// password differ by their salt, so the hash is copied across in the table.
// The binding then says nothing about whose challenge it is; the subject must.
func TestVerify2FARefusesAnotherAccountsChallengeWithTheSameBinding(t *testing.T) {
	m := newTestManager(t)
	alice := createUser(t, m, "alice", "shared-passphrase")
	bob := createUser(t, m, "bob", "shared-passphrase")
	if _, err := m.db.Exec(m.dialect.Rebind(
		"UPDATE users SET password = (SELECT password FROM users WHERE id = ?) WHERE id = ?"), alice, bob); err != nil {
		t.Fatal(err)
	}
	m.revokeSessions(bob)
	secret, _, _, err := m.beginTOTPEnrolment(alice)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := m.currentBinding(alice)
	bb, _ := m.currentBinding(bob)
	if ab != bb {
		t.Fatalf("precondition: the two accounts should share a binding (%s vs %s)", ab, bb)
	}
	assertRefusedChallenge(t, m, challengeFor(t, m, bob), alice, code)
}

func TestVerify2FARefusesAnExpiredChallenge(t *testing.T) {
	m := newTestManager(t)
	id, code := enrolledAccount(t, m, "alice")
	old, err := m.issueChallenge(id, time.Now().Add(-ChallengeLifetime-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	assertRefusedChallenge(t, m, old, id, code)
}

func TestVerify2FARefusesASessionAsChallenge(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "alice", "correct-horse-battery")
	session, _, err := m.Authenticate("alice", "correct-horse-battery", "")
	if err != nil || session == "" {
		t.Fatalf("sign-in before enrolment: %v", err)
	}
	secret, _ := enroll(t, m, id, "correct-horse-battery")
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyToken(session); err != nil {
		t.Fatalf("the session should still be live: %v", err)
	}
	assertRefusedChallenge(t, m, session, id, code)
}

// TestVerify2FARefusesAChallengeWithoutItsPurpose: a token encrypted the way a
// challenge is, naming the account and bound to its state, but not saying it
// is a challenge. Nothing mints one; the check is for whatever does next.
func TestVerify2FARefusesAChallengeWithoutItsPurpose(t *testing.T) {
	m := newTestManager(t)
	id, code := enrolledAccount(t, m, "alice")
	binding, err := m.currentBinding(id)
	if err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	tok.SetExpiration(time.Now().Add(time.Minute))
	tok.SetSubject(id)
	tok.SetString(SessionBindingClaim, binding)
	assertRefusedChallenge(t, m, tok.V4Encrypt(m.keys.Load().sign, challengeImplicit), id, code)
}

// TestChallengeVoidedByAccountChanges: the challenge is bound to the account
// state a session is, so what ends a session ends the sign-in step under way.
func TestChallengeVoidedByAccountChanges(t *testing.T) {
	for name, change := range map[string]func(*Manager, string) error{
		"password": func(m *Manager, id string) error { return m.ChangePassword(id, "rotated-password") },
		"sign-out": func(m *Manager, id string) error { return m.EndSessions(id) },
		"disabled": func(m *Manager, id string) error { return m.SetUserDisabled(id, true) },
	} {
		t.Run(name, func(t *testing.T) {
			m := newTestManager(t)
			id, code := enrolledAccount(t, m, "alice")
			challenge := challengeFor(t, m, id)
			if err := change(m, id); err != nil {
				t.Fatal(err)
			}
			assertRefusedChallenge(t, m, challenge, id, code)
		})
	}
}

func TestVerifyTokenRefusesAChallenge(t *testing.T) {
	m := newTestManager(t)
	id, _ := enrolledAccount(t, m, "alice")
	if claims, err := m.VerifyToken(challengeFor(t, m, id)); err == nil {
		t.Fatalf("a challenge verified as a session: %+v", claims)
	}
}

// TestVerifyTokenRefusesATokenWithAPurpose: a token with every claim a
// session has, valid for the account, but carrying a purpose. A session never
// does, so whatever minted it, it is not one.
func TestVerifyTokenRefusesATokenWithAPurpose(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "alice", "correct-horse-battery")
	binding, err := m.currentBinding(id)
	if err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	tok.SetExpiration(time.Now().Add(time.Minute))
	tok.SetString("id", id)
	tok.SetString("role", RoleAdmin)
	tok.SetString(SessionBindingClaim, binding)
	tok.SetString(PurposeClaim, purposeTwoFactorChallenge)
	if claims, err := m.VerifyToken(tok.V4Encrypt(m.keys.Load().sign, nil)); err == nil {
		t.Fatalf("a token with a purpose verified as a session: %+v", claims)
	}
}

// TestRoutePasetoMiddlewareCannotReadAChallenge: a route's PASETO middleware
// accepts any token its secret decrypts. An operator who gives it the session
// key accepts dashboard sessions there; a challenge -- proof of a password
// alone, on an account with 2FA -- must not be one more thing it accepts.
func TestRoutePasetoMiddlewareCannotReadAChallenge(t *testing.T) {
	m := newTestManager(t)
	id, _ := enrolledAccount(t, m, "alice")
	v, err := mwauth.NewPasetoVerifier(testSymmetricKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := v.VerifyToken(challengeFor(t, m, id)); err == nil {
		t.Fatalf("a route's PASETO middleware accepted a challenge: %v", claims)
	}
}

// TestRefusedChallengesAreNotCounted: anyone who knows an id can send a step
// with no challenge. Counting it would let them lock the account out.
func TestRefusedChallengesAreNotCounted(t *testing.T) {
	m := newTestManager(t)
	id, code := enrolledAccount(t, m, "alice")
	for range MaxFailedAttempts + 1 {
		assertRefusedChallenge(t, m, "", id, "000000")
	}
	if ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, code); !ok || err != nil {
		t.Fatalf("the owner's sign-in after refused steps: ok=%v err=%v", ok, err)
	}
}

func TestAuthenticateCarriesAChallengeWhenASecondFactorIsOwed(t *testing.T) {
	m := newTestManager(t)
	id, code := enrolledAccount(t, m, "alice")
	pending := createUser(t, m, "bob", "the-other-accounts-pw")
	if err := m.SetTwoFactorPending(pending, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user, pw, id string
		owed         error
	}{
		{"alice", "correct-horse-battery", id, ErrTwoFactorRequired},
		{"bob", "the-other-accounts-pw", pending, ErrTwoFactorSetupRequired},
	} {
		token, _, err := m.Authenticate(tc.user, tc.pw, "")
		if !errors.Is(err, tc.owed) || token != "" {
			t.Fatalf("%s: token=%q err=%v, want %v and no session", tc.user, token, err, tc.owed)
		}
		challenge := ChallengeFrom(err)
		if challenge == "" {
			t.Fatalf("%s: no challenge in %v", tc.user, err)
		}
		if strings.Contains(err.Error(), challenge) {
			t.Errorf("%s: the error text carries the challenge, so logging it writes one down", tc.user)
		}
		if m.checkChallenge(challenge, tc.id) != nil {
			t.Errorf("%s: Authenticate's challenge does not verify", tc.user)
		}
	}
	if ok, _, _, err := m.Verify2FA(ChallengeFrom(authErr(m, "alice", "correct-horse-battery")), id, code); !ok || err != nil {
		t.Fatalf("password, then challenge, then code: ok=%v err=%v", ok, err)
	}
}

func authErr(m *Manager, username, password string) error {
	_, _, err := m.Authenticate(username, password, "")
	return err
}

func TestWrongPasswordCarriesNoChallenge(t *testing.T) {
	m := newTestManager(t)
	enrolledAccount(t, m, "alice")
	if c := ChallengeFrom(authErr(m, "alice", "wrong")); c != "" {
		t.Fatalf("a wrong password earned a challenge")
	}
}
