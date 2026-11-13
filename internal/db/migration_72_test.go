// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// Migration 72 adds users.two_factor_last_step, the last TOTP step an account
// signed in with (review L1). An existing account starts at 0, below every real
// step, so the upgrade refuses nobody's next code.
func TestEveryAccountRecordsItsLastTOTPStep(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		conn, dialect, err := Open("sqlite://" + filepath.Join(t.TempDir(), "m72.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration72(t, conn, dialect)
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration72(t, conn, dialect)
	})
}

// checkMigration72 migrates, re-runs migration 72 over the result, and checks
// an account written without the column reads 0.
func checkMigration72(t *testing.T, conn *sql.DB, dialect Dialect) {
	t.Helper()
	if err := Migrate(conn, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := migration(t, 72).Up(conn, dialect); err != nil {
		t.Fatalf("migration 72 over an installation that already has it: %v", err)
	}
	const id = "m72-account"
	if _, err := conn.Exec(dialect.Rebind(`DELETE FROM users WHERE id = ?`), id); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(dialect.Rebind(`INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)`),
		id, id, "x", "viewer"); err != nil {
		t.Fatalf("insert an account: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(dialect.Rebind(`DELETE FROM users WHERE id = ?`), id) })
	var step int64 = -1
	if err := conn.QueryRow(dialect.Rebind(`SELECT two_factor_last_step FROM users WHERE id = ?`), id).Scan(&step); err != nil {
		t.Fatalf("read two_factor_last_step: %v", err)
	}
	if step != 0 {
		t.Fatalf("two_factor_last_step of an account written without it = %d; want 0", step)
	}
}
