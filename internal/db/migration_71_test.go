// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// Migration 71 indexes user_mitigations(ja4h) and ip_mitigations(expires_at).
// Before it, the fingerprint checks' "fingerprint = ? OR ja4h = ?" could use
// the primary key for one half only, so SQLite planned a full scan of the
// table for every check; with it, both halves are index lookups.
func TestMitigationLookupsAreIndexed(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		conn, dialect, err := Open("sqlite://" + filepath.Join(t.TempDir(), "m71.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration71(t, conn, dialect)

		plan := sqlitePlan(t, conn, `SELECT status FROM user_mitigations
			WHERE (fingerprint = 'a|b' OR ja4h = 'a|b') AND updated_at > '2026-01-01'`)
		if strings.Contains(plan, "SCAN user_mitigations") {
			t.Fatalf("the fingerprint check still scans user_mitigations:\n%s", plan)
		}
		plan = sqlitePlan(t, conn, `SELECT ip FROM ip_mitigations WHERE expires_at < '2026-01-01' LIMIT 10`)
		if !strings.Contains(plan, "idx_ip_mitigations_expires_at") {
			t.Fatalf("the lapsed-shun read does not use the expires_at index:\n%s", plan)
		}
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration71(t, conn, dialect)
	})
}

// checkMigration71 migrates, re-runs migration 71 over the result, and checks
// both indexes exist.
func checkMigration71(t *testing.T, conn *sql.DB, dialect Dialect) {
	t.Helper()
	if err := Migrate(conn, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := migration(t, 71).Up(conn, dialect); err != nil {
		t.Fatalf("migration 71 over an installation that already has it: %v", err)
	}
	q := `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`
	if dialect.Driver == DriverPostgres {
		q = `SELECT COUNT(*) FROM pg_indexes WHERE indexname = $1`
	}
	for _, name := range []string{"idx_user_mitigations_ja4h", "idx_ip_mitigations_expires_at"} {
		var n int
		if err := conn.QueryRow(q, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("index %s: found %d, want 1", name, n)
		}
	}
}

func sqlitePlan(t *testing.T, conn *sql.DB, query string) string {
	t.Helper()
	rows, err := conn.Query("EXPLAIN QUERY PLAN " + query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		b.WriteString(detail + "\n")
	}
	return b.String()
}
