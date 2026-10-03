// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestAuthenticate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_auth_table.db")

	_ = logger.Init(false)
	m, err := NewManager(dbPath, "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer m.Close()

	// Seed user
	user := &gateonv1.User{
		Username: "testuser",
		Password: "test-user-passphrase",
		Role:     RoleOperator,
	}
	if err := m.UpsertUser(user); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	tests := []struct {
		name     string
		username string
		password string
		wantErr  error
	}{
		{"Valid login", "testuser", "test-user-passphrase", nil},
		{"Invalid password", "testuser", "wrong", ErrInvalidCredentials},
		{"Invalid user", "nonexistent", "password", ErrInvalidCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := m.Authenticate(tt.username, tt.password, "")
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccountLockout(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_auth.db")

	_ = logger.Init(false)
	m, err := NewManager(dbPath, "12345678901234567890123456789012", logger.Default())
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer m.Close()

	user := &gateonv1.User{
		Username: "admin",
		Password: "lockout-passphrase",
		Role:     RoleAdmin,
	}
	if err := m.UpsertUser(user); err != nil {
		t.Fatalf("failed to upsert user: %v", err)
	}

	now := time.Now()
	m.knownAttempts.SetClock(func() time.Time { return now })
	const source = "203.0.113.9"

	// Fail login MaxFailedAttempts times from one source.
	for range MaxFailedAttempts {
		_, _, err := m.Authenticate("admin", "wrong", source)
		if err != ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got %v", err)
		}
	}

	// The next attempt from that source is locked, the right password too.
	_, _, err = m.Authenticate("admin", "lockout-passphrase", source)
	if err != ErrAccountLocked {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	// The password step no longer writes the stored count: that is the second
	// factor's, and a stranger's guesses must not reach it (ADR 0050).
	var lockedUntil sql.NullTime
	err = m.db.QueryRow("SELECT locked_until FROM users WHERE username = ?", "admin").Scan(&lockedUntil)
	if err != nil {
		t.Fatalf("failed to query locked_until: %v", err)
	}
	if lockedUntil.Valid {
		t.Errorf("a sign-in lock was written to the account: locked_until = %v", lockedUntil.Time)
	}

	// The lock lasts LockoutDuration, then the right password works.
	now = now.Add(LockoutDuration)
	_, _, err = m.Authenticate("admin", "lockout-passphrase", source)
	if err != nil {
		t.Errorf("expected successful login once the lock ended, got %v", err)
	}
}
