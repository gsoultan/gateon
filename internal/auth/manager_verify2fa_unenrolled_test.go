// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// TestVerify2FARefusesAccountWithNoEnrolledSecret: an account that never
// enrolled a second factor has an empty two_factor_secret. pquerna/otp
// base32-decodes "" to an empty HMAC key without error, so the six-digit code
// derived from that empty key validates against every such account.
func TestVerify2FARefusesAccountWithNoEnrolledSecret(t *testing.T) {
	m := newTestManager(t)
	id := createUser(t, m, "alice", "s3cret-pass")

	code, err := totp.GenerateCode("", time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	ok, token, _, err := m.Verify2FA(id, code)
	if ok || token != "" {
		t.Fatalf("Verify2FA issued a session for an account with no enrolled secret: ok=%v token=%q", ok, token)
	}
	if !errors.Is(err, ErrInvalidTwoFactorCode) {
		t.Fatalf("expected ErrInvalidTwoFactorCode, got %v", err)
	}
}
