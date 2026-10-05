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

// A row already stored under the key a group moves to is one of the group's
// rows. Migration 68 used to read only keys with a colon, so a plain IPv4 row
// was deleted unread and the v4-mapped row of the same address replaced it,
// whatever either held: an operator's block on 198.51.100.11 next to an older
// release stored as ::ffff:198.51.100.11 came out released (review 3, F2).
func TestMigration68MergesTheRowAlreadyAtTheKey(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		conn, dialect, err := Open("sqlite://" + filepath.Join(t.TempDir(), "m68k.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration68TargetRow(t, conn, dialect)
	})
	t.Run("postgres", func(t *testing.T) {
		conn, dialect, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkMigration68TargetRow(t, conn, dialect)
	})
}

// m68Row is one ip_mitigations row a migration 68 case starts with. The times
// are offsets from now; a nil offset is NULL.
type m68Row struct {
	ip, status, reason   string
	updated              time.Duration
	unmitigated, expires *time.Duration
}

func ago(d time.Duration) *time.Duration { return &d }

func checkMigration68TargetRow(t *testing.T, conn *sql.DB, dialect Dialect) {
	t.Helper()
	if err := Migrate(conn, dialect); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Exec(`DELETE FROM ip_mitigations`) })
	for _, tc := range []struct {
		name string
		rows []m68Row
		key  string
		want string
	}{{
		// The review's case: the block in force is the plain row.
		name: "IPv4 block in force beside an older mapped release",
		rows: []m68Row{
			{ip: "198.51.100.11", status: "mitigated", reason: "operator", updated: -time.Hour},
			{ip: "::ffff:198.51.100.11", status: "unmitigated", reason: "released", updated: -2 * time.Hour, unmitigated: ago(-2 * time.Hour)},
		},
		key: "198.51.100.11", want: "mitigated/operator",
	}, {
		name: "open-ended IPv4 block beside a mapped block that lapses later",
		rows: []m68Row{
			{ip: "198.51.100.12", status: "mitigated", reason: "operator", updated: -2 * time.Hour},
			{ip: "::ffff:198.51.100.12", status: "mitigated", reason: "IP shunning triggered", updated: -time.Minute, expires: ago(time.Hour)},
		},
		key: "198.51.100.12", want: "mitigated/operator",
	}, {
		name: "a release beats a lapsed IPv4 shun",
		rows: []m68Row{
			{ip: "198.51.100.13", status: "mitigated", reason: "IP shunning triggered", updated: -time.Minute, expires: ago(-time.Minute)},
			{ip: "::ffff:198.51.100.13", status: "unmitigated", reason: "released", updated: -time.Hour, unmitigated: ago(-time.Hour)},
		},
		key: "198.51.100.13", want: "unmitigated/released",
	}, {
		// The other direction still holds: the mapped row's block wins.
		name: "mapped block in force beside an IPv4 release",
		rows: []m68Row{
			{ip: "198.51.100.14", status: "unmitigated", reason: "released", updated: -time.Minute, unmitigated: ago(-time.Minute)},
			{ip: "::ffff:198.51.100.14", status: "mitigated", reason: "operator", updated: -time.Hour},
		},
		key: "198.51.100.14", want: "mitigated/operator",
	}, {
		// An IPv6 key has a colon, so its row was always read; pinned so it stays so.
		name: "IPv6 block in force beside a later release at the /64 key",
		rows: []m68Row{
			{ip: "2001:db8:7:7::", status: "unmitigated", reason: "released", updated: -time.Minute, unmitigated: ago(-time.Minute)},
			{ip: "2001:db8:7:7::9", status: "mitigated", reason: "operator", updated: -time.Hour},
		},
		key: "2001:db8:7:7::", want: "mitigated/operator",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			runMigration68Case(t, conn, dialect, tc.rows)
			got := m68Rows(t, conn)
			if len(got) != 1 || got[tc.key] != tc.want {
				t.Errorf("after migration 68: %v, want only %s = %s", got, tc.key, tc.want)
			}
		})
	}
}

// runMigration68Case empties ip_mitigations, inserts rows and runs migration 68.
func runMigration68Case(t *testing.T, conn *sql.DB, dialect Dialect, rows []m68Row) {
	t.Helper()
	if _, err := conn.Exec(`DELETE FROM ip_mitigations`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	at := func(d *time.Duration) any {
		if d == nil {
			return nil
		}
		return now.Add(*d).Format(time.DateTime)
	}
	insert := dialect.Rebind(`INSERT INTO ip_mitigations (ip, status, reason, mitigated_at, unmitigated_at, updated_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	for _, r := range rows {
		updated := r.updated
		if _, err := conn.Exec(insert, r.ip, r.status, r.reason, at(ago(-3*time.Hour)),
			at(r.unmitigated), at(&updated), at(r.expires)); err != nil {
			t.Fatalf("insert %s: %v", r.ip, err)
		}
	}
	if err := migration(t, 68).Up(conn, dialect); err != nil {
		t.Fatalf("migration 68: %v", err)
	}
}

// m68Rows reads ip_mitigations as ip -> "status/reason".
func m68Rows(t *testing.T, conn *sql.DB) map[string]string {
	t.Helper()
	rows, err := conn.Query(`SELECT ip, status, COALESCE(reason, '') FROM ip_mitigations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var ip, status, reason string
		if err := rows.Scan(&ip, &status, &reason); err != nil {
			t.Fatal(err)
		}
		got[ip] = status + "/" + reason
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return got
}
