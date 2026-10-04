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

// Migration 68 moves each IPv6 address shun to its /64's key, the key the
// block list is now read under (ADR 0058); without it a block an operator set
// on one IPv6 address before the upgrade would be enforced by nothing.
func TestIPv6ShunsMoveToTheirSlashSixtyFour(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		conn, dialect, err := Open("sqlite://" + filepath.Join(t.TempDir(), "m68.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration68(t, conn, dialect)
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration68(t, conn, dialect)
	})
}

func checkMigration68(t *testing.T, conn *sql.DB, dialect Dialect) {
	t.Helper()
	if err := Migrate(conn, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := conn.Exec(`DELETE FROM ip_mitigations`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(`DELETE FROM ip_mitigations`) })
	now := time.Now().UTC()
	at := func(d time.Duration) any { return now.Add(d).Format(time.DateTime) }
	insert := dialect.Rebind(`INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, unmitigated_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	for _, r := range []struct {
		ip, status, reason   string
		unmitigated, expires any
	}{
		// One /64: an operator's block, a lapsed automatic shun and a release.
		{"2001:db8:1:2::5", "mitigated", "operator", nil, nil},
		{"2001:db8:1:2::6", "mitigated", "IP shunning triggered", nil, at(-time.Hour)},
		{"2001:db8:1:2:ffff::1", "unmitigated", "released", at(-time.Minute), nil},
		// Another /64: an automatic shun in force alone.
		{"2001:db8:9:9::1", "mitigated", "Anomaly detection: x", nil, at(time.Hour)},
		// A v4-mapped address, and IPv4, which stays.
		{"::ffff:198.51.100.9", "mitigated", "operator", nil, nil},
		{"198.51.100.10", "mitigated", "operator", nil, nil},
	} {
		if _, err := conn.Exec(insert, r.ip, r.status, r.reason, at(-2*time.Hour), r.unmitigated, at(-2*time.Hour), r.expires); err != nil {
			t.Fatalf("insert %s: %v", r.ip, err)
		}
	}

	if err := migration(t, 68).Up(conn, dialect); err != nil {
		t.Fatalf("migration 68: %v", err)
	}

	got := map[string]string{}
	rows, err := conn.Query(`SELECT ip, status, COALESCE(reason, ''), expires_at FROM ip_mitigations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip, status, reason string
		var expires sql.NullTime
		if err := rows.Scan(&ip, &status, &reason, &expires); err != nil {
			t.Fatal(err)
		}
		got[ip] = status + "/" + reason
		if ip == "2001:db8:9:9::" && (!expires.Valid || !expires.Time.After(now)) {
			t.Errorf("the moved automatic shun lost its expiry: %v", expires)
		}
	}
	want := map[string]string{
		"2001:db8:1:2::": "mitigated/operator",
		"2001:db8:9:9::": "mitigated/Anomaly detection: x",
		"198.51.100.9":   "mitigated/operator",
		"198.51.100.10":  "mitigated/operator",
	}
	if len(got) != len(want) {
		t.Errorf("rows after migration 68: %v, want %v", got, want)
	}
	for ip, w := range want {
		if got[ip] != w {
			t.Errorf("%s: %q, want %q (all rows: %v)", ip, got[ip], w, got)
		}
	}
	// Running it again changes nothing.
	if err := migration(t, 68).Up(conn, dialect); err != nil {
		t.Fatalf("migration 68 again: %v", err)
	}
}
