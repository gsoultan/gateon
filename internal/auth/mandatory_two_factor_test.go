// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

// Every account has a second factor (ADR 0087). These pin the three places
// that is decided: the password step never ends a sign-in, no session is ever
// minted for an account without one, and a session that exists anyway -- one
// the previous release minted before the rule -- stops working.

func TestPasswordAloneNeverSignsIn(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "paula", "correct-horse-battery")

	token, user, err := m.Authenticate("paula", "correct-horse-battery", "")
	if !errors.Is(err, ErrTwoFactorSetupRequired) {
		t.Fatalf("a correct password on an account with no second factor: err = %v, want ErrTwoFactorSetupRequired", err)
	}
	if token != "" {
		t.Fatalf("the password alone minted a session %q", token)
	}
	if user == nil || user.Id != id {
		t.Fatalf("the enrolment step needs the account it is for, got %+v", user)
	}
	if ChallengeFrom(err) == "" {
		t.Fatal("no challenge: the enrolment could not be completed")
	}
}

func TestEnrolmentAtSignInNeedsNoAdministrator(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "quinn", "correct-horse-battery")

	_, _, err := m.Authenticate("quinn", "correct-horse-battery", "")
	challenge := ChallengeFrom(err)
	secret, _, codes, enrolID, err := m.EnrollPending2FA("quinn", "correct-horse-battery", "")
	if err != nil {
		t.Fatalf("enrolment at sign-in refused an account nobody had flagged: %v", err)
	}
	if enrolID != id || len(codes) == 0 {
		t.Fatalf("enrolment answered id %q and %d recovery codes", enrolID, len(codes))
	}
	code, _ := freshCode(t, m, secret)
	ok, token, _, err := m.Verify2FA(challenge, id, code)
	if err != nil || !ok || token == "" {
		t.Fatalf("first code: ok=%v token=%q err=%v", ok, token, err)
	}
	if _, err := m.VerifyToken(token); err != nil {
		t.Fatalf("the session the enrolment ended with does not verify: %v", err)
	}
	if _, _, err := m.Authenticate("quinn", "correct-horse-battery", ""); !errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("after enrolling, the password step answered %v, want ErrTwoFactorRequired", err)
	}
}

func TestNoSessionIsMintedForAnAccountWithoutASecondFactor(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "rhea", "correct-horse-battery")

	token, _, err := m.issueToken(&gateonv1.User{Id: id, Username: "rhea", Role: RoleAdmin})
	if !errors.Is(err, ErrTwoFactorSetupRequired) || token != "" {
		t.Fatalf("issueToken for an unenrolled account: token %q, err %v", token, err)
	}
}

// legacyBinding is the session binding the previous release computed: the
// digest had no second-factor input at all.
func legacyBinding(passwordHash, role string) string {
	h := sha256.New()
	writeField(h, passwordHash)
	writeField(h, role)
	writeField(h, "0")
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// mintLegacySession is a password-only session as the previous release
// issued it for an account with no second factor.
func mintLegacySession(t *testing.T, m *Manager, id string) string {
	t.Helper()
	var hash, role string
	if err := m.db.QueryRow(m.dialect.Rebind("SELECT password, role FROM users WHERE id = ?"), id).Scan(&hash, &role); err != nil {
		t.Fatal(err)
	}
	tok := paseto.NewToken()
	now := time.Now()
	tok.SetIssuedAt(now)
	tok.SetNotBefore(now)
	tok.SetExpiration(now.Add(TokenLifetime))
	tok.SetSubject(id)
	tok.SetString("id", id)
	tok.SetString("role", role)
	tok.SetString(SessionBindingClaim, legacyBinding(hash, role))
	return tok.V4Encrypt(m.keys.Load().sign, nil)
}

func TestAPasswordOnlySessionFromBeforeTheRuleIsRefused(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "sven", "correct-horse-battery")

	if _, err := m.VerifyToken(mintLegacySession(t, m, id)); err == nil {
		t.Fatal("a password-only session of an account with no second factor still verifies")
	}
}

func TestAnEnrolledAccountKeepsItsSessionsAcrossTheUpgrade(t *testing.T) {
	m := newTestManager(t)
	id, _ := enrolledAccount(t, m, "tara")

	// The digest of an enrolled account is the one the previous release
	// computed, so the upgrade signs nobody out who already had 2FA.
	if _, err := m.VerifyToken(mintLegacySession(t, m, id)); err != nil {
		t.Fatalf("an enrolled account's session from before the upgrade was refused: %v", err)
	}
}

// Setup2FA on an account that already had a second factor wrote
// two_factor_enabled = false and the new, unconfirmed secret before any code
// was checked. Closing the dialog there left the account signing in with the
// password alone, and its old authenticator and recovery codes dead.
func TestReenrolmentKeepsTheWorkingFactorUntilTheNewOneIsConfirmed(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "ursula", "correct-horse-battery")
	oldSecret, oldCodes := enroll(t, m, id, "correct-horse-battery")

	e, err := m.Setup2FA(id, "correct-horse-battery")
	if err != nil {
		t.Fatalf("Setup2FA on an enrolled account: %v", err)
	}
	// Abandoned here.
	if _, _, err := m.Authenticate("ursula", "correct-horse-battery", ""); !errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("an abandoned re-enrolment left the password step answering %v, want ErrTwoFactorRequired", err)
	}
	oldCode, _ := freshCode(t, m, oldSecret)
	if ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, oldCode); !ok || err != nil {
		t.Fatalf("the old authenticator stopped working before the new one was confirmed: ok=%v err=%v", ok, err)
	}
	if ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, oldCodes[0]); !ok || err != nil {
		t.Fatalf("an old recovery code stopped working before the new factor was confirmed: ok=%v err=%v", ok, err)
	}

	// Confirmed: the new factor replaces the old one.
	newCode, _ := freshCode(t, m, e.Secret)
	if ok, _, _, err := m.Verify2FA(e.Challenge, id, newCode); !ok || err != nil {
		t.Fatalf("confirming the new authenticator: ok=%v err=%v", ok, err)
	}
	stale, _ := freshCode(t, m, oldSecret)
	if ok, _, _, _ := m.Verify2FA(challengeFor(t, m, id), id, stale); ok {
		t.Fatal("the replaced authenticator still signs in")
	}
	if ok, _, _, _ := m.Verify2FA(challengeFor(t, m, id), id, oldCodes[1]); ok {
		t.Fatal("a recovery code of the replaced factor still signs in")
	}
}

// TestATOTPCodeSignsInOnce is the regression test for review L1.
//
// Root cause: a code was checked against the secret and the clock only, so it
// was accepted every time it was presented while its step was in the window.
func TestATOTPCodeSignsInOnce(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "vera", "correct-horse-battery")
	secret, _ := enroll(t, m, id, "correct-horse-battery")

	code, _ := freshCode(t, m, secret)
	if ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, code); !ok || err != nil {
		t.Fatalf("the code, first time: ok=%v err=%v", ok, err)
	}
	if ok, token, _, err := m.Verify2FA(challengeFor(t, m, id), id, code); ok || token != "" || !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Fatalf("the same code again: ok=%v token=%q err=%v, want ErrInvalidTwoFactorCode", ok, token, err)
	}
	// An earlier step's code, still inside the window, is refused once a
	// later one has been used.
	earlier, _ := totp.GenerateCode(secret, m.now().Add(-30*time.Second))
	if earlier != code {
		if ok, _, _, _ := m.Verify2FA(challengeFor(t, m, id), id, earlier); ok {
			t.Fatal("a code from before the last one used still signs in")
		}
	}
	// The next one works.
	next, _ := freshCode(t, m, secret)
	if ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, next); !ok || err != nil {
		t.Fatalf("the next code: ok=%v err=%v", ok, err)
	}
}
