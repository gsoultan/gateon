// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"os"
	"testing"
)

// The migration suite was only ever exercised against SQLite, which is the
// permissive one: it accepts loose types, ignores most constraint mismatches,
// and will happily store a string in an INTEGER column. Postgres will not, and
// gateon advertises support for it — so a migration can pass every test here
// and still fail on the first Postgres deployment, which is the worst place to
// discover it because migrations run at startup.
//
// This runs against a real Postgres when GATEON_TEST_POSTGRES_DSN is set and
// skips otherwise, so a developer without a database is not blocked while CI,
// which has a service container, always runs it.
//
//	GATEON_TEST_POSTGRES_DSN='postgres://user:pass@localhost:5432/db?sslmode=disable' \
//	    go test ./internal/db/ -run Postgres
func TestMigrate_AllMigrations_Postgres(t *testing.T) {
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN not set; skipping Postgres migration test")
	}

	pg, dialect, err := Open(dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer pg.Close()

	if dialect.Driver != DriverPostgres {
		t.Fatalf("DSN did not resolve to Postgres, got driver %q", dialect.Driver)
	}
	if err := pg.Ping(); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}

	if err := Migrate(pg, dialect); err != nil {
		t.Fatalf("Migrate on Postgres failed: %v", err)
	}

	// The highest registered migration must be recorded, not merely the run
	// reporting success: a migration that silently no-ops leaves the schema
	// behind the code that expects it.
	highest := highestRegisteredID()
	applied, err := isApplied(pg, dialect, highest)
	if err != nil {
		t.Fatalf("isApplied(%d): %v", highest, err)
	}
	if !applied {
		t.Errorf("migration %d ran but was not recorded as applied", highest)
	}

	// Idempotency matters more on Postgres than on SQLite, because a partially
	// applied DDL statement there aborts the surrounding transaction and every
	// later statement in it.
	if err := Migrate(pg, dialect); err != nil {
		t.Fatalf("Migrate second run on Postgres failed (not idempotent): %v", err)
	}
}

// highestRegisteredID reports the largest migration ID the binary knows about,
// so the assertion above does not have to be edited every time one is added.
func highestRegisteredID() int {
	highest := 0
	for _, m := range migrations {
		if m.ID > highest {
			highest = m.ID
		}
	}
	return highest
}
