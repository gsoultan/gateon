// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
)

const testSecret = "dev-secret-please-change-me-0123"

func newManager(t *testing.T, dbURL string) *auth.Manager {
	t.Helper()
	_ = logger.Init(false)
	mgr, err := auth.NewManager(dbURL, testSecret, logger.Default())
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

func devDB(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "dev", ".data")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "gateon-dev.db")
}

// TestSeedSignsInAsAdminAdmin is the point of the seed: after it runs, the
// dashboard accepts admin/admin, a password every API refuses to set.
func TestSeedSignsInAsAdminAdmin(t *testing.T) {
	dbURL := devDB(t)
	mgr := newManager(t, dbURL)
	for _, a := range accounts {
		weak, err := seedAccount(mgr, dbURL, a, passwordFor(a, ""))
		if err != nil {
			t.Fatalf("seed %s: %v", a.username, err)
		}
		if !weak {
			t.Errorf("seed %s: want the weak-password path, got the policy path", a.username)
		}
	}
	// A second run resets rather than duplicates.
	if _, err := seedAccount(mgr, dbURL, accounts[0], "admin"); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	_, user, err := mgr.Authenticate("admin", "admin", "127.0.0.1")
	if err != nil {
		t.Fatalf("admin/admin did not sign in: %v", err)
	}
	if user.Role != auth.RoleAdmin {
		t.Errorf("role = %q, want %q", user.Role, auth.RoleAdmin)
	}
	if _, _, err := mgr.Authenticate("viewer", "viewer", "127.0.0.1"); err != nil {
		t.Errorf("viewer/viewer did not sign in: %v", err)
	}
}

// TestSeedRefusesWeakPasswordOutsideDevData pins the guard: the same seed
// pointed at a database that is not under dev/.data stores nothing weak.
func TestSeedRefusesWeakPasswordOutsideDevData(t *testing.T) {
	dbURL := filepath.Join(t.TempDir(), "gateon.db")
	mgr := newManager(t, dbURL)
	_, err := seedAccount(mgr, dbURL, accounts[0], "admin")
	if !errors.Is(err, errNotDevDatabase) {
		t.Fatalf("err = %v, want errNotDevDatabase", err)
	}
	if _, _, err := mgr.Authenticate("admin", "admin", "127.0.0.1"); err == nil {
		t.Fatal("admin/admin signed in on a database outside dev/.data")
	}
}

// TestSeedStrongOverrideNeedsNoDevDatabase: a password the policy accepts goes
// through the normal API, wherever the database is.
func TestSeedStrongOverrideNeedsNoDevDatabase(t *testing.T) {
	dbURL := filepath.Join(t.TempDir(), "gateon.db")
	mgr := newManager(t, dbURL)
	weak, err := seedAccount(mgr, dbURL, accounts[0], "correct-horse-battery")
	if err != nil || weak {
		t.Fatalf("weak=%v err=%v, want the policy path", weak, err)
	}
}

func TestIsDevDatabase(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"dev/.data/gateon-dev.db", true},
		{"sqlite:dev/.data/gateon-dev.db", true},
		{"sqlite:///repo/dev/.data/x.db?_pragma=foo", true},
		{"/var/lib/gateon/gateon.db", false},
		{"gateon.db", false},
		{"dev/.data", false},
		{"dev/.data-old/x.db", false},
		{"/repo/notdev/.data/x.db", false},
		{":memory:", false},
		{"postgres://gateon:gateon@127.0.0.1:55432/gateon?sslmode=disable", true},
		{"postgresql://u:p@localhost/gateon", true},
		{"postgres://u:p@[::1]:5432/gateon", true},
		{"postgres://u:p@10.0.0.5:5432/gateon", false},
		{"postgres://u:p@db.example.com/gateon", false},
		{"postgres://u:p@127.0.0.1/gateon?host=db.example.com", false},
		{"mysql://u:p@127.0.0.1/gateon", false},
	}
	for _, c := range cases {
		if got := isDevDatabase(c.url); got != c.want {
			t.Errorf("isDevDatabase(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestRedactHidesPassword(t *testing.T) {
	got := redact("postgres://gateon:s3cret@db.example.com/gateon")
	if got == "" || strings.Contains(got, "s3cret") {
		t.Fatalf("redact leaked the password: %q", got)
	}
}
