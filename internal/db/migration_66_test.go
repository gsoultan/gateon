// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/testutil"
)

// Migration 66 gives ip_mitigations an expiry (ADR 0031). A shun written
// before it by an automatic path gets the expiry it would have had -- the
// first rung, fifteen minutes from when it was written -- so most lapse at
// once; an operator's block keeps none and holds until released.
func TestLegacyAutomaticShunsLapseAndOperatorBlocksHold(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		conn, dialect, err := Open("sqlite://" + filepath.Join(t.TempDir(), "m66.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration66(t, conn, dialect)
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration66(t, conn, dialect)
	})
}

func checkMigration66(t *testing.T, conn *sql.DB, dialect Dialect) {
	t.Helper()
	if err := Migrate(conn, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := conn.Exec(`DELETE FROM ip_mitigations`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(`DELETE FROM ip_mitigations`) })
	insert := dialect.Rebind(`INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`)
	legacy := []struct{ ip, status, reason string }{
		{"198.51.100.1", "mitigated", "IP shunning triggered: 3 unique malicious users detected from this IP"},
		{"198.51.100.2", "mitigated", "Anomaly detection: Potential brute force detected"},
		{"198.51.100.3", "mitigated", "Manual recommendation applied via API"},
		{"198.51.100.4", "mitigated", "blocked after the pentest report"},
		{"198.51.100.5", "unmitigated", "Alert playbook: stuffing"},
	}
	for _, row := range legacy {
		// Written the way the gateway wrote them before the expiry existed.
		if _, err := conn.Exec(insert, row.ip, row.status, row.reason, time.Now().Add(-2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	if err := migration(t, 66).Up(conn, dialect); err != nil {
		t.Fatalf("migration 66: %v", err)
	}

	for _, row := range legacy {
		var mitigatedAt, expiresAt sql.NullTime
		q := dialect.Rebind(`SELECT mitigated_at, expires_at FROM ip_mitigations WHERE ip = ?`)
		if err := conn.QueryRow(q, row.ip).Scan(&mitigatedAt, &expiresAt); err != nil {
			t.Fatal(err)
		}
		automatic := row.ip == "198.51.100.1" || row.ip == "198.51.100.2"
		switch {
		case automatic && !expiresAt.Valid:
			t.Errorf("%s (%q) was written by an automatic path and was given no expiry: it would "+
				"never lapse", row.ip, row.reason)
		case automatic && !lastsFirstRung(expiresAt.Time.Sub(mitigatedAt.Time)):
			t.Errorf("%s lapses %v after it was written, want the first rung, 15m",
				row.ip, expiresAt.Time.Sub(mitigatedAt.Time))
		case !automatic && expiresAt.Valid:
			t.Errorf("%s (%q, %s) was given an expiry; an operator's block and a release keep none",
				row.ip, row.reason, row.status)
		}
	}
}

// lastsFirstRung reports whether d is fifteen minutes, give or take the
// second the expiry is written to (Postgres keeps mitigated_at finer).
func lastsFirstRung(d time.Duration) bool {
	return d > 15*time.Minute-time.Second && d <= 15*time.Minute
}

// migration returns the registered migration with id.
func migration(t *testing.T, id int) Migration {
	t.Helper()
	for _, m := range migrations {
		if m.ID == id {
			return m
		}
	}
	t.Fatalf("migration %d is not registered", id)
	return Migration{}
}
