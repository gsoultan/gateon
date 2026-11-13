// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package authtest signs accounts in for tests outside internal/auth.
//
// Every account has a second factor (ADR 0087), so a password no longer ends a
// sign-in: the first one enrols an authenticator and the session comes from
// its first code. Tests that only need a session -- to call an RPC, to watch it
// be revoked -- get one from SignIn, which runs the sign-in the dashboard runs.
// Tests whose subject is the password step read it through PasswordStep.
//
// Nothing outside a _test.go file imports this package, so none of it reaches
// the binary.
package authtest

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

// secrets holds the TOTP secret SignIn enrolled each account with, by account
// id, so a later SignIn of the same account can answer its code. Ids are
// random per account, so tests sharing it do not collide.
var secrets sync.Map

// Remember records secret as account id's second factor, for an account a test
// enrolled itself.
func Remember(id, secret string) { secrets.Store(id, secret) }

// Secret is the second factor SignIn enrolled account id with, or "".
func Secret(id string) string {
	s, _ := secrets.Load(id)
	v, _ := s.(string)
	return v
}

// PasswordStep is the password step alone. It answers nil where Authenticate
// asks for the second factor, so "no error" still reads as "the password was
// accepted" in tests about the first factor.
func PasswordStep(svc auth.Service, username, password, source string) (*gateonv1.User, error) {
	_, user, err := svc.Authenticate(username, password, source)
	if errors.Is(err, auth.ErrTwoFactorSetupRequired) || errors.Is(err, auth.ErrTwoFactorRequired) {
		return user, nil
	}
	return user, err
}

// SignIn is a whole sign-in: the password, the enrolment the first time, then
// a code. It returns the session and the account, and fails the test if any
// step is refused.
func SignIn(t testing.TB, svc auth.Service, username, password, source string) (string, *gateonv1.User) {
	t.Helper()
	token, user, err := TrySignIn(svc, username, password, source)
	if err != nil || token == "" {
		t.Fatalf("signing in as %s: token %q, err %v", username, token, err)
	}
	return token, user
}

// TrySignIn is SignIn for a test that expects a refusal: it returns the error
// of the first step that refused.
func TrySignIn(svc auth.Service, username, password, source string) (string, *gateonv1.User, error) {
	_, user, err := svc.Authenticate(username, password, source)
	challenge := auth.ChallengeFrom(err)
	var secret string
	switch {
	case errors.Is(err, auth.ErrTwoFactorSetupRequired):
		var id string
		secret, _, _, id, err = svc.EnrollPending2FA(username, password, source)
		if err != nil {
			return "", nil, err
		}
		Remember(id, secret)
		user = &gateonv1.User{Id: id}
	case errors.Is(err, auth.ErrTwoFactorRequired):
		if secret = Secret(user.GetId()); secret == "" {
			return "", user, errors.New("authtest: " + username + " has a second factor this package did not enrol")
		}
	default:
		return "", user, err
	}
	code, err := Code(secret)
	if err != nil {
		return "", nil, err
	}
	_, token, signedIn, err := svc.Verify2FA(challenge, user.GetId(), code)
	return token, signedIn, err
}

// spent is the last TOTP step Code handed out for each secret.
var spent sync.Map // secret -> int64

// Code is a TOTP code from secret for a step this package has not handed out
// before. The gateway accepts each step's code once (review L1), so a test
// that signs one account in twice inside thirty seconds must not present the
// same code twice. It takes the earliest step in the accepted window -- the
// current one and one either side -- after the last it handed out, and fails
// when all three are spent rather than wait: a test that needs a fourth sign-in
// of one account inside a minute needs a manager whose clock it can move.
func Code(secret string) (string, error) {
	code, _, err := CodeAt(secret)
	return code, err
}

// CodeAt is Code, and also the instant inside the code's step, for a test that
// pins a manager's clock to it so the time the sign-in takes cannot move the
// code out of its window.
func CodeAt(secret string) (string, time.Time, error) {
	cur := time.Now().Unix() / 30
	last, _ := spent.Load(secret)
	lastStep, _ := last.(int64)
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		if step > lastStep {
			spent.Store(secret, step)
			at := time.Unix(step*30+15, 0)
			code, err := totp.GenerateCode(secret, at)
			return code, at, err
		}
	}
	return "", time.Time{}, errors.New("authtest: every TOTP step in the window was already used for this secret")
}
