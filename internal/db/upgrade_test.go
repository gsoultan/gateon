// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Migrations run at startup, against whatever the operator already has. Every
// test in this package before these ones started from an empty database, which
// is the one case an upgrade is never in: a fresh install exercises the DDL but
// not a single row of existing data, so a migration that rewrites a table,
// narrows a column or rebuilds a primary key passes on an empty schema and
// fails on the first real deployment.
//
// These tests reconstruct the schema a past release shipped, put data in it,
// and run the rest of the chain -- which is what an upgrading operator does.

// shippedRelease records how far the migration chain had advanced at a tagged
// release, so an upgrade from that release can be reproduced.
//
// Deriving these is mechanical:
//
//	git show <tag>:internal/db/migrations.go |
//	    grep -oE 'Register\([0-9]+,' | grep -oE '[0-9]+' | sort -n | tail -1
type shippedRelease struct {
	tag          string
	lastMigraton int
}

// The oldest supported upgrade origin first. New entries go at the end; none of
// these numbers can change, because the release they describe has shipped.
var shippedReleases = []shippedRelease{
	{tag: "v1.5.0", lastMigraton: 30},
	{tag: "v1.9.9", lastMigraton: 40},
	{tag: "v2.0.0", lastMigraton: 41},
	{tag: "v2.3.0", lastMigraton: 52},
	{tag: "v2.5.3", lastMigraton: 58},
	{tag: "v2.6.0", lastMigraton: 62},
}

// upgradeTarget is a database an upgrade can be rehearsed against. dsn is empty
// for SQLite, which gets a private file per subtest instead of a shared server.
type upgradeTarget struct {
	name string
	dsn  string
}

// upgradeTargets returns SQLite always, plus Postgres when a DSN is configured.
// MySQL is deliberately absent: migration 2 puts two TEXT columns in a PRIMARY
// KEY, which MySQL has never accepted, so no MySQL database has ever reached
// even migration 3 and there is no upgrade from one to rehearse.
func upgradeTargets() []upgradeTarget {
	targets := []upgradeTarget{{name: "sqlite"}}
	if dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN"); dsn != "" {
		targets = append(targets, upgradeTarget{name: "postgres", dsn: dsn})
	}
	return targets
}

// url resolves the connection string for one subtest. Every SQLite subtest gets
// its own file: sharing one made each subtest inherit the previous one's rows
// and collide on primary keys, which reads as a migration bug and is not one.
func (target upgradeTarget) url(t *testing.T) string {
	t.Helper()
	if target.dsn != "" {
		return target.dsn
	}
	return "sqlite:" + filepath.Join(t.TempDir(), "gateon.db")
}

// migrateUpTo runs every migration with an ID at or below last, reproducing the
// schema as of a past release. It mirrors Migrate's loop rather than calling it,
// because Migrate deliberately offers no way to stop part way.
func migrateUpTo(database *sql.DB, dialect Dialect, last int) error {
	if err := ensureMigrationsTable(database, dialect); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].ID < migrations[j].ID })

	for _, m := range migrations {
		if m.ID > last {
			break
		}
		applied, err := isApplied(database, dialect, m.ID)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", m.ID, err)
		}
		if applied {
			continue
		}
		if err := m.Up(database, dialect); err != nil {
			return fmt.Errorf("migration %d (%s): %w", m.ID, m.Name, err)
		}
		if err := markApplied(database, dialect, m.ID, m.Name); err != nil {
			return fmt.Errorf("mark migration %d applied: %w", m.ID, err)
		}
	}
	return nil
}

// openTarget dials a target and returns a probe over it, reset to empty.
func openTarget(t *testing.T, target upgradeTarget) (*sql.DB, Dialect, schemaProbe) {
	t.Helper()
	database, dialect, err := Open(target.url(t))
	if err != nil {
		t.Fatalf("open %s: %v", target.name, err)
	}
	t.Cleanup(func() { _ = database.Close() })

	probe := schemaProbe{t: t, db: database, dialect: dialect}
	probe.reset()
	return database, dialect, probe
}

// TestUpgradeFromShippedReleaseKeepsData is the regression this package was
// missing: a populated database from every supported release must survive the
// whole remaining chain with every row still readable.
func TestUpgradeFromShippedReleaseKeepsData(t *testing.T) {
	const rowsPerTable = 5

	for _, target := range upgradeTargets() {
		for _, release := range shippedReleases {
			t.Run(target.name+"/from-"+release.tag, func(t *testing.T) {
				assertReleaseIsReachable(t, release)
				database, dialect, probe := openTarget(t, target)

				if err := migrateUpTo(database, dialect, release.lastMigraton); err != nil {
					t.Fatalf("could not reconstruct %s schema: %v", release.tag, err)
				}
				before := probe.seed(rowsPerTable)
				if len(before) == 0 {
					t.Fatalf("%s schema seeded no tables; the fixture is not testing anything", release.tag)
				}

				if err := Migrate(database, dialect); err != nil {
					t.Fatalf("upgrading a populated %s database failed: %v", release.tag, err)
				}

				assertNoDataLoss(t, probe, before)
			})
		}
	}
}

// assertReleaseIsReachable catches a stale table: a release boundary above the
// highest registered migration means the entry was mistyped, and the upgrade it
// claims to cover would silently run nothing.
func assertReleaseIsReachable(t *testing.T, release shippedRelease) {
	t.Helper()
	if highest := highestRegisteredID(); release.lastMigraton > highest {
		t.Fatalf("%s claims migration %d but only %d are registered",
			release.tag, release.lastMigraton, highest)
	}
}

// assertNoDataLoss compares row counts across the upgrade.
func assertNoDataLoss(t *testing.T, probe schemaProbe, before map[string]int) {
	t.Helper()
	tables := make([]string, 0, len(before))
	for table := range before {
		tables = append(tables, table)
	}
	sort.Strings(tables)

	after := probe.rowCounts(tables)
	for _, table := range tables {
		got, ok := after[table]
		if !ok {
			continue // rowCounts already reported it as unreadable
		}
		if got != before[table] {
			t.Errorf("table %q: %d rows before upgrade, %d after", table, before[table], got)
		}
	}
}

// TestUpgradeConvergesOnFreshInstallSchema guards the other half of the
// property. Data surviving is not sufficient: if an upgraded database ends up
// without a column a fresh install has, the binary is running queries against a
// shape that deployment does not have, and only the query that needs it fails --
// at runtime, on whichever endpoint touches it first.
func TestUpgradeConvergesOnFreshInstallSchema(t *testing.T) {
	for _, target := range upgradeTargets() {
		for _, release := range shippedReleases {
			t.Run(target.name+"/from-"+release.tag, func(t *testing.T) {
				database, dialect, probe := openTarget(t, target)

				if err := migrateUpTo(database, dialect, release.lastMigraton); err != nil {
					t.Fatalf("could not reconstruct %s schema: %v", release.tag, err)
				}
				probe.seed(3)
				if err := Migrate(database, dialect); err != nil {
					t.Fatalf("upgrade from %s failed: %v", release.tag, err)
				}
				upgraded := probe.columnNames()

				probe.reset()
				if err := Migrate(database, dialect); err != nil {
					t.Fatalf("fresh install failed: %v", err)
				}
				fresh := probe.columnNames()

				assertSchemaCoversFresh(t, upgraded, fresh)
			})
		}
	}
}

// assertSchemaCoversFresh reports anything a fresh install has that an upgraded
// database lacks. The reverse -- a table or column left over from an older
// release -- is not an error: migrations retire data deliberately slowly, and
// SQLite cannot drop a column at all.
func assertSchemaCoversFresh(t *testing.T, upgraded, fresh map[string][]string) {
	t.Helper()
	tables := make([]string, 0, len(fresh))
	for table := range fresh {
		tables = append(tables, table)
	}
	sort.Strings(tables)

	for _, table := range tables {
		have, ok := upgraded[table]
		if !ok {
			t.Errorf("table %q exists on a fresh install but not after upgrading", table)
			continue
		}
		present := make(map[string]bool, len(have))
		for _, name := range have {
			present[name] = true
		}
		for _, name := range fresh[table] {
			if !present[name] {
				t.Errorf("column %q.%q exists on a fresh install but not after upgrading", table, name)
			}
		}
	}
}
