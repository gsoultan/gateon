// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package inits

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/pquerna/otp/totp"
)

// enrolUnder creates an account on dbPath with a second factor encrypted under
// key, and returns its id and TOTP secret.
func enrolUnder(t *testing.T, dbPath, key string) (id, secret string) {
	t.Helper()
	m, err := auth.NewManager(dbPath, key, logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = m.Close() }()
	u := &gateonv1.User{Username: "gina", Password: "correct-horse-battery", Role: auth.RoleAdmin}
	if err := m.UpsertUser(u); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	enrolment, err := m.Setup2FA(u.Id, "correct-horse-battery")
	if err != nil {
		t.Fatalf("Setup2FA: %v", err)
	}
	secret = enrolment.Secret
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _, err := m.Verify2FA(enrolment.Challenge, u.Id, code); err != nil || !ok {
		t.Fatalf("enrolling: ok=%v err=%v", ok, err)
	}
	return u.Id, secret
}

// TestBootMovesSecondFactorsFromThePreviousSessionKey: a gateway restarted with
// a changed session key -- global.json edited, the reference it names rotated
// at the source -- came up with every 2FA account unable to complete a sign-in,
// and said nothing. With the previous key in GATEON_PREVIOUS_SESSION_KEY,
// startup moves the second factors to the new one.
func TestBootMovesSecondFactorsFromThePreviousSessionKey(t *testing.T) {
	const oldKey = "0123456789abcdef0123456789abcdef"
	const newKey = "fedcba9876543210fedcba9876543210"
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth.db")
	id, secret := enrolUnder(t, dbPath, oldKey)

	globalFile := filepath.Join(dir, "global.json")
	conf := fmt.Sprintf(`{"auth": {"paseto_secret": %q, "database_url": %q}}`, newKey, dbPath)
	if err := os.WriteFile(globalFile, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(previousSessionKeyEnv, oldKey)

	m := InitGlobalConfig(globalFile, config.NewGlobalRegistry(globalFile))
	if m == nil {
		t.Fatal("startup built no auth manager")
	}
	t.Cleanup(func() { _ = m.Close() })

	// The code is for an instant the manager is told is now, so how long the
	// sign-in and the second step take -- seconds of production-cost bcrypt,
	// many times that on a loaded host under -race -- cannot move it out of
	// its window. It was generated for the wall clock, which could.
	at := time.Now()
	m.SetClock(func() time.Time { return at })
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	_, _, signIn := m.Authenticate("gina", "correct-horse-battery", "")
	ok, token, _, err := m.Verify2FA(auth.ChallengeFrom(signIn), id, code)
	if err != nil || !ok || token == "" {
		t.Fatalf("after a restart with a changed key, and the previous key given, the second factor does not verify: ok=%v err=%v",
			ok, err)
	}
}
