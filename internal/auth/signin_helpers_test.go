// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"sync"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

// A password no longer ends a sign-in (ADR 0088). passwordStep is the password
// step alone, for tests whose subject is the first factor -- the lockout, the
// hash gate, a password change -- and which used to read "no error" as "the
// password was accepted": it answers nil where Authenticate now asks for the
// second factor.
func passwordStep(m *Manager, username, password, source string) (string, *gateonv1.User, error) {
	token, user, err := m.Authenticate(username, password, source)
	if errors.Is(err, ErrTwoFactorSetupRequired) || errors.Is(err, ErrTwoFactorRequired) {
		return token, user, nil
	}
	return token, user, err
}

// enrolledSecrets remembers the TOTP secret signIn enrolled each account with,
// so a later signIn of the same account can answer its code.
var enrolledSecrets sync.Map // id -> secret

// signIn is a whole sign-in, as the dashboard runs it: the password, then the
// enrolment the first time, then the code. It returns the session.
func signIn(t *testing.T, m *Manager, username, password, source string) (string, *gateonv1.User, error) {
	t.Helper()
	_, user, err := m.Authenticate(username, password, source)
	challenge := ChallengeFrom(err)
	var secret string
	switch {
	case errors.Is(err, ErrTwoFactorSetupRequired):
		var id string
		secret, _, _, id, err = m.EnrollPending2FA(username, password, source)
		if err != nil {
			return "", nil, err
		}
		enrolledSecrets.Store(id, secret)
		user = &gateonv1.User{Id: id}
	case errors.Is(err, ErrTwoFactorRequired):
		s, ok := enrolledSecrets.Load(user.Id)
		if !ok {
			t.Fatalf("signIn: %s has a second factor this helper did not enrol", username)
		}
		secret = s.(string)
	default:
		return "", user, err
	}
	code, err := freshCode(t, m, secret)
	if err != nil {
		t.Fatal(err)
	}
	_, token, user, err := m.Verify2FA(challenge, user.Id, code)
	return token, user, err
}

// freshCode is a TOTP code from secret for a step m has not spent yet, and it
// stops m's clock in the middle of that step, so the code is checked at the
// instant it was made for however long the host takes to present it.
//
// Each step's code is accepted once (review L1), so a test that signs one
// account in several times inside thirty seconds needs a later step each time:
// it takes the earliest step in the accepted window -- the current one and one
// either side -- after the last one spent, or the step after that.
//
// It used to leave m's clock running, and take the step before the current
// one first. That code is valid only until the current step ends, so whenever
// the wall clock crossed a thirty-second boundary between making the code and
// checking it, the check ran a step later and refused it as invalid. That is
// why TestEnrollPendingRejectedOnceEnrolled failed now and then on a commit
// that passed on the next run: its enrolment helper's own code was refused.
func freshCode(t *testing.T, m *Manager, secret string) (string, error) {
	t.Helper()
	cur := m.now().Unix() / 30
	// The latest step any account spent: more cautious than the one account
	// needs, never less, and read from the database so a second manager on it
	// sees what the first spent.
	var last int64
	if err := m.db.QueryRow("SELECT COALESCE(MAX(two_factor_last_step), 0) FROM users").Scan(&last); err != nil {
		t.Fatal(err)
	}
	step := max(cur-1, last+1)
	at := time.Unix(step*30+15, 0)
	m.SetClock(func() time.Time { return at })
	return totp.GenerateCode(secret, at)
}

// rememberSecret records secret as the factor of account id for signIn.
func rememberSecret(id, secret string) { enrolledSecrets.Store(id, secret) }
