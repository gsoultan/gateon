// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/auth/lockout"
	"golang.org/x/crypto/bcrypt"
)

const (
	ownerAddr    = "198.51.100.7"
	attackerAddr = "203.0.113.9"
	ownerPass    = "owners-own-passphrase"
)

// TestAStrangerCannotLockTheOwnerOut is M6 as the review ran it: five wrong
// passwords for "admin" from one address, then the right password from
// another. The lockout counted per username, so the owner got "account
// locked" -- and five requests every fifteen minutes kept them out for good.
func TestAStrangerCannotLockTheOwnerOut(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "admin", ownerPass)

	for range MaxFailedAttempts {
		if _, _, err := m.Authenticate("admin", "a-guess", attackerAddr); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attacker's guess: err = %v, want ErrInvalidCredentials", err)
		}
	}
	token, _, err := m.Authenticate("admin", ownerPass, ownerAddr)
	if err != nil || token == "" {
		t.Fatalf("the owner, from another address, after a stranger's %d wrong passwords: err = %v, want a session",
			MaxFailedAttempts, err)
	}
}

// TestGuessingFromOneSourceIsStillThrottled is the other half: the attacker's
// source is locked, so a sixth guess is refused -- even the right password --
// and the same /24 is the same source.
func TestGuessingFromOneSourceIsStillThrottled(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "admin", ownerPass)

	for range MaxFailedAttempts {
		_, _, _ = m.Authenticate("admin", "a-guess", attackerAddr)
	}
	for _, addr := range []string{attackerAddr, "203.0.113.200", "203.0.113.200:61000"} {
		if _, _, err := m.Authenticate("admin", ownerPass, addr); !errors.Is(err, ErrAccountLocked) {
			t.Errorf("the right password from %s, in the locked /24: err = %v, want ErrAccountLocked", addr, err)
		}
	}
}

// TestSpreadGuessingLeavesOnlyKnownSourcesIn is the per-account backstop: an
// attacker spreading guesses over many sources, each under the per-source
// limit, puts the account under attack; then a source the account has never
// signed in from is refused even with the right password, and the owner's own
// source -- remembered in the database -- is not.
func TestSpreadGuessingLeavesOnlyKnownSourcesIn(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "admin", ownerPass)
	if _, _, err := m.Authenticate("admin", ownerPass, ownerAddr); err != nil {
		t.Fatalf("the owner's first sign-in: %v", err)
	}

	for i := range lockout.AccountLimit {
		addr := "203.0." + strconv.Itoa(i/(lockout.PairLimit-1)) + ".9"
		if _, _, err := m.Authenticate("admin", "a-guess", addr); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("spread guess %d from %s: err = %v, want ErrInvalidCredentials", i, addr, err)
		}
	}
	if _, _, err := m.Authenticate("admin", ownerPass, "192.0.2.50"); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("the right password from a new source under attack: err = %v, want ErrAccountLocked", err)
	}
	if token, _, err := m.Authenticate("admin", ownerPass, ownerAddr); err != nil || token == "" {
		t.Errorf("the owner from a known source under attack: err = %v, want a session", err)
	}
}

// TestKnownSourcesAreRememberedAndBounded: a sign-in records its source, a
// repeat does not add it twice, and only the most recent few are kept.
func TestKnownSourcesAreRememberedAndBounded(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "admin", ownerPass)
	for i := range maxLoginSources + 3 {
		addr := "198.51." + strconv.Itoa(i) + ".7"
		if _, _, err := m.Authenticate("admin", ownerPass, addr); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.Authenticate("admin", ownerPass, addr); err != nil {
			t.Fatal(err)
		}
	}
	got := m.loginSources(id)
	if len(got) != maxLoginSources {
		t.Fatalf("remembered %d sources, want %d: %v", len(got), maxLoginSources, got)
	}
	if got[0] != "198.51.10.0/24" || slices.Contains(got, "198.51.0.0/24") {
		t.Errorf("not the most recent first, oldest dropped: %v", got)
	}
}

// TestUnknownUsernameAnswersLikeARealOne: M10's second half. Only a real
// account could ever answer "locked", so five guesses told a caller whether a
// username existed.
func TestUnknownUsernameAnswersLikeARealOne(t *testing.T) {
	m := newTestManager(t)
	createUser(t, m, "admin", ownerPass)
	for _, name := range []string{"admin", "no-such-user"} {
		for range MaxFailedAttempts {
			if _, _, err := m.Authenticate(name, "a-guess", attackerAddr); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("%s: err = %v, want ErrInvalidCredentials", name, err)
			}
		}
		if _, _, err := m.Authenticate(name, "a-guess", attackerAddr); !errors.Is(err, ErrAccountLocked) {
			t.Errorf("%s after %d guesses: err = %v, want ErrAccountLocked", name, MaxFailedAttempts, err)
		}
	}
}

// TestUnknownUsernameTakesAsLongAsARealOne is M10: an unknown username was
// answered in 1-8 ms and a real one in about 55, because only a real one paid
// for a bcrypt comparison. The real account's hash is written at the
// production cost here, since this package's tests otherwise hash at the
// minimum.
func TestUnknownUsernameTakesAsLongAsARealOne(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "admin", ownerPass)
	hash, err := bcrypt.GenerateFromPassword([]byte(ownerPass), productionBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.db.Exec(m.dialect.Rebind(QueryUpdatePassword), string(hash), id); err != nil {
		t.Fatal(err)
	}
	dummyHash() // paid once per process, not per attempt

	realTime := medianSignIn(t, m, "admin")
	unknown := medianSignIn(t, m, "no-such-user")
	if unknown*4 < realTime {
		t.Errorf("an unknown username answered in %v, a real one in %v: the difference names the accounts that exist",
			unknown, realTime)
	}
}

func medianSignIn(t *testing.T, m *Manager, username string) time.Duration {
	t.Helper()
	var d []time.Duration
	for i := range 3 {
		start := time.Now()
		if _, _, err := m.Authenticate(username, "a-guess", "192.0.2."+strconv.Itoa(i)); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%s: err = %v", username, err)
		}
		d = append(d, time.Since(start))
	}
	slices.Sort(d)
	return d[1]
}

// TestACorrectPasswordDoesNotResetTheSecondFactorsCount: the password step
// cleared the stored failure count on every correct password, so whoever held
// the password could sign in again after every fourth wrong code and guess
// TOTP codes without ever reaching the lock.
func TestACorrectPasswordDoesNotResetTheSecondFactorsCount(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "admin", ownerPass)
	enroll(t, m, id, ownerPass)

	for range MaxFailedAttempts - 1 {
		if ok, _, _, _ := m.Verify2FA(challengeFor(t, m, id), id, "000000"); ok {
			t.Fatal("a wrong code was accepted")
		}
	}
	if _, _, err := m.Authenticate("admin", ownerPass, ownerAddr); !errors.Is(err, ErrTwoFactorRequired) {
		t.Fatalf("the password step: err = %v, want ErrTwoFactorRequired", err)
	}
	if _, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, "000000"); !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Fatalf("the fifth wrong code: err = %v", err)
	}
	if _, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, "000000"); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("after %d wrong codes with a correct password in between: err = %v, want ErrAccountLocked",
			MaxFailedAttempts, err)
	}
}
