// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// lockoutZoneEnv tells a re-executed test binary which local zone it was
// started under, and that it is the child that should do the work.
const lockoutZoneEnv = "GATEON_TEST_LOCKOUT_ZONE"

// TestLockoutLastsItsDurationInEveryLocalZone.
//
// users.locked_until is TIMESTAMP -- without time zone -- on Postgres, and the
// lockout wrote time.Now().Add(LockoutDuration) into it: a time in the
// gateway's local zone. Postgres drops the offset of a value bound to that
// type and keeps the wall clock, and lib/pq hands the wall clock back as UTC.
// So on a host behind UTC the lock came back already expired -- five wrong
// passwords, and the sixth guess was answered like the first, with no lockout
// at all -- and on a host ahead of UTC it lasted hours instead of fifteen
// minutes. SQLite stores the offset and never showed it.
//
// The local zone is process-wide, so each zone runs in a re-executed copy of
// this test binary with TZ set; the parent only launches them.
func TestLockoutLastsItsDurationInEveryLocalZone(t *testing.T) {
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN not set; the zone is only lost on Postgres")
	}
	if zone := os.Getenv(lockoutZoneEnv); zone != "" {
		assertLockoutWindow(t, dsn, zone)
		return
	}
	for _, zone := range []string{"America/New_York", "Asia/Tokyo"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLockoutLastsItsDurationInEveryLocalZone$", "-test.count=1")
		cmd.Env = append(os.Environ(), "TZ="+zone, lockoutZoneEnv+"="+zone)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("gateway running in %s: %v\n%s", zone, err, out)
		}
	}
}

func assertLockoutWindow(t *testing.T, dsn, zone string) {
	t.Helper()
	if name, _ := time.Now().Zone(); name == "UTC" {
		t.Fatalf("TZ=%s did not take effect; the child is running in UTC and proves nothing", zone)
	}
	t.Setenv("GATEON_DATA_DIR", t.TempDir())
	m, err := NewManager(dsn, "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = m.Close() }()

	username := fmt.Sprintf("lockout-%s-%d", filepath.Base(zone), time.Now().UnixNano())
	if err := m.UpsertUser(&gateonv1.User{Username: username, Password: "right-password", Role: RoleViewer}); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	defer func() { _, _ = m.DB().Exec(m.Dialect().Rebind("DELETE FROM users WHERE username = ?"), username) }()

	for range MaxFailedAttempts {
		if _, _, err := m.Authenticate(username, "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password: got %v, want ErrInvalidCredentials", err)
		}
	}
	if _, _, err := m.Authenticate(username, "right-password"); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("in %s the account was not locked after %d failures: Authenticate = %v",
			zone, MaxFailedAttempts, err)
	}

	// NULL once a login got through: a successful Authenticate clears it.
	var until sql.NullTime
	if err := m.DB().QueryRow(m.Dialect().Rebind("SELECT locked_until FROM users WHERE username = ?"), username).Scan(&until); err != nil {
		t.Fatalf("read locked_until: %v", err)
	}
	if left := time.Until(until.Time); until.Valid && left > LockoutDuration+time.Minute {
		t.Errorf("in %s the lock runs for %v, not %v", zone, left.Round(time.Minute), LockoutDuration)
	}
}
