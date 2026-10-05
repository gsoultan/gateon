// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// Migration 69 persists whether a stored threat is held against its source
// (ADR 0059). A row written before it gets what its type says: a detection
// only a control that let the request through recorded is observed, unless
// the row records a refusal; a leak found in a response is unattributed;
// everything else stays held.
func TestStoredThreatsLearnWhetherTheyAreHeldAgainstTheirSource(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		conn, dialect, err := Open("sqlite://" + filepath.Join(t.TempDir(), "m69.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration69(t, conn, dialect)
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration69(t, conn, dialect)
	})
}

// legacyThreat is a row as the gateway wrote it before migration 69, and the
// flags the migration must give it.
type legacyThreat struct {
	id, typ, action        string
	observed, unattributed bool
}

func checkMigration69(t *testing.T, conn *sql.DB, dialect Dialect) {
	t.Helper()
	if err := Migrate(conn, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := conn.Exec(`DELETE FROM security_threats`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(`DELETE FROM security_threats`) })
	legacy := []legacyThreat{
		{"m69-audit", "waf_detected", "detected", true, false},
		{"m69-sqli", "sqli_detected", "detected", true, false},
		{"m69-probe", "probe_detected", "flagged", true, false},
		{"m69-posture", "device_posture_change", "", true, false},
		{"m69-leak", "data_exposure", "redacted", false, true},
		{"m69-waf-block", "waf_blocked", "blocked", false, false},
		{"m69-trap", "honeypot_triggered", "blocked", false, false},
		{"m69-detected-and-refused", "generic_attack", "blocked", false, false},
	}
	insert := dialect.Rebind(`INSERT INTO security_threats (id, type, source_ip, score, details, action_taken)
		VALUES (?, ?, '100.64.60.10', 50, '', ?)`)
	for _, row := range legacy {
		if _, err := conn.Exec(insert, row.id, row.typ, row.action); err != nil {
			t.Fatal(err)
		}
	}

	if err := migration(t, 69).Up(conn, dialect); err != nil {
		t.Fatalf("migration 69 over an installation that already has it: %v", err)
	}

	read := dialect.Rebind(`SELECT observed, unattributed FROM security_threats WHERE id = ?`)
	for _, row := range legacy {
		var observed, unattributed bool
		if err := conn.QueryRow(read, row.id).Scan(&observed, &unattributed); err != nil {
			t.Fatal(err)
		}
		if observed != row.observed || unattributed != row.unattributed {
			t.Errorf("%s (%s, %q) is observed=%v unattributed=%v, want %v/%v",
				row.id, row.typ, row.action, observed, unattributed, row.observed, row.unattributed)
		}
	}
}
