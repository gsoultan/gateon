// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// TestAValidCodeIsNotHeldUpByTheRecoveryCodes: Verify2FA compared the code
// against all ten recovery-code hashes -- bcrypt, at the production cost --
// before it looked at the TOTP code. Under the race detector that took 6 s on
// an idle host and over 30 s on a loaded one, long enough for the code to pass
// out of its window before it was checked; internal/inits'
// TestBootMovesSecondFactorsFromThePreviousSessionKey failed that way in a
// full -race run. The recovery codes here are written at cost 12 so their
// price shows: ten of them are seconds, and a valid TOTP code must not pay it.
func TestAValidCodeIsNotHeldUpByTheRecoveryCodes(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "admin", ownerPass)
	secret, _ := enroll(t, m, id, ownerPass)

	slow, err := bcrypt.GenerateFromPassword([]byte("NOT-A-REAL-RECOVERY-CODE"), 12)
	if err != nil {
		t.Fatal(err)
	}
	ten := strings.TrimSuffix(strings.Repeat(string(slow)+",", 10), ",")
	if _, err := m.db.Exec(m.dialect.Rebind("UPDATE users SET recovery_codes = ? WHERE id = ?"), ten, id); err != nil {
		t.Fatal(err)
	}

	at := time.Now()
	m.SetClock(func() time.Time { return at })
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, code)
	took := time.Since(start)
	if err != nil || !ok {
		t.Fatalf("a valid code: ok=%v err=%v", ok, err)
	}
	// One cost-12 comparison is about 250 ms here and four times that under
	// -race; ten were compared before the code. Half of one is the budget.
	if one := bcryptOnce(t, slow); took > one/2 {
		t.Errorf("a valid TOTP code took %v to verify, more than half of one recovery-code comparison (%v): "+
			"the recovery codes are being compared first", took, one)
	}
}

func bcryptOnce(t *testing.T, hash []byte) time.Duration {
	t.Helper()
	start := time.Now()
	_ = bcrypt.CompareHashAndPassword(hash, []byte("x"))
	return time.Since(start)
}

// TestTheTOTPClockIsTheOneCodesAreCheckedAgainst: a code generated for an
// instant verifies when the manager's clock says that instant, however long
// ago it was, and one generated two windows away does not.
func TestTheTOTPClockIsTheOneCodesAreCheckedAgainst(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "admin", ownerPass)
	secret, _ := enroll(t, m, id, ownerPass)

	at := time.Now().Add(-time.Hour)
	m.SetClock(func() time.Time { return at })
	stale, err := totp.GenerateCode(secret, at.Add(-90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _, _ := m.Verify2FA(challengeFor(t, m, id), id, stale); ok {
		t.Fatal("a code three windows from the clock was accepted")
	}
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _, err := m.Verify2FA(challengeFor(t, m, id), id, code); err != nil || !ok {
		t.Fatalf("a code for the manager's clock, an hour ago: ok=%v err=%v", ok, err)
	}
}
