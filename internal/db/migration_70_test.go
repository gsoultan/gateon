// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// Migration 70 gives every route a stream_mode (ADR 0064). A route stored
// before it -- by v1.1.0, which wrote no such column -- reads back 0, auto:
// the rule every route ran before the field existed. Re-running the migration
// over an installation that already has it changes nothing.
func TestRoutesStoredBeforeStreamModeKeepTheAutomaticRule(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		conn, dialect, err := Open("sqlite://" + filepath.Join(t.TempDir(), "m70.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration70(t, conn, dialect)
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration70(t, conn, dialect)
	})
}

func checkMigration70(t *testing.T, conn *sql.DB, dialect Dialect) {
	t.Helper()
	if err := Migrate(conn, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	const id = "m70-legacy-route"
	cleanup := dialect.Rebind(`DELETE FROM routes WHERE id = ?`)
	if _, err := conn.Exec(cleanup, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(cleanup, id) })
	// The columns v1.1.0's route store wrote, and no others.
	legacy := dialect.Rebind(`INSERT INTO routes (id, name, type, entrypoints, rule, priority, middlewares,
		service_id, tls_config, disabled) VALUES (?, 'legacy', 'http', '', 'PathPrefix(` + "`/`" + `)', 0, '', 'svc', '', FALSE)`)
	if _, err := conn.Exec(legacy, id); err != nil {
		t.Fatal(err)
	}

	if err := migration(t, 70).Up(conn, dialect); err != nil {
		t.Fatalf("migration 70 over an installation that already has it: %v", err)
	}

	var mode int
	if err := conn.QueryRow(dialect.Rebind(`SELECT stream_mode FROM routes WHERE id = ?`), id).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 0 {
		t.Fatalf("a route stored before migration 70 reads stream_mode %d, want 0 (auto)", mode)
	}
}
