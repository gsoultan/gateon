// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMigrate_AllMigrations(t *testing.T) {
	sqliteDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open sqlite in-memory db: %v", err)
	}
	defer sqliteDB.Close()

	dialect := Dialect{Driver: DriverSQLite}

	if err := Migrate(sqliteDB, dialect); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	// Verify that migration 55 was applied
	applied, err := isApplied(sqliteDB, dialect, 55)
	if err != nil {
		t.Fatalf("isApplied for migration 55 failed: %v", err)
	}
	if !applied {
		t.Errorf("migration 55 was not marked as applied")
	}

	// Re-run Migrate to ensure idempotency
	if err := Migrate(sqliteDB, dialect); err != nil {
		t.Fatalf("Migrate second run failed: %v", err)
	}
}
