// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
)

// TestReclaimSQLDiskReturnsPagesToOS is the regression test for the telemetry
// SQLite file growing without bound while prune() happily deleted rows.
//
// Two independent defects each disabled disk reclaim, and the fix needs both:
//
//  1. auto_vacuum stayed NONE. db.Open bakes journal_mode(WAL) into the DSN, so
//     the file exists before any pragma runs, and SQLite will not change
//     auto_vacuum on an existing file without a VACUUM. A bare
//     `PRAGMA auto_vacuum=INCREMENTAL` was therefore ignored.
//     ensureIncrementalAutoVacuum sets it and VACUUMs once.
//  2. incremental_vacuum was run with ExecContext. modernc.org/sqlite performs
//     a row-returning PRAGMA only as its rows are stepped, and Exec does not
//     iterate, so it reclaimed nothing even once auto_vacuum was right.
//     reclaimSQLDisk now drives it through a drained Query.
//
// The test grows the database, prunes it the way the store does, runs the real
// reclaimSQLDisk, and asserts the file actually shrank and the freelist drained.
func TestReclaimSQLDiskReturnsPagesToOS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reclaim.db")
	database, dialect, err := db.Open(path)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if dialect.Driver != db.DriverSQLite {
		t.Fatalf("expected sqlite driver, got %q", dialect.Driver)
	}

	// Exactly the init sequence of initStore's SQLite branch.
	if _, err := database.Exec(SQLitePragmas); err != nil {
		t.Fatalf("apply SQLitePragmas: %v", err)
	}
	// Root cause #1, asserted: the plain pragma path leaves auto_vacuum off, so
	// without the ensure step there is nothing for incremental_vacuum to do.
	if mode := queryInt(t, database, QueryAutoVacuum); mode == autoVacuumIncremental {
		t.Fatalf("precondition failed: auto_vacuum is already INCREMENTAL (%d) before ensure; test would be vacuous", mode)
	}
	if err := ensureIncrementalAutoVacuum(context.Background(), database); err != nil {
		t.Fatalf("ensureIncrementalAutoVacuum: %v", err)
	}
	if mode := queryInt(t, database, QueryAutoVacuum); mode != autoVacuumIncremental {
		t.Fatalf("auto_vacuum=%d after ensure, want %d (INCREMENTAL)", mode, autoVacuumIncremental)
	}

	// Grow the file well past a page, then delete it all, like prune() does.
	if _, err := database.Exec(`CREATE TABLE blobs (id INTEGER PRIMARY KEY, v BLOB)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	for i := 0; i < 400; i++ {
		if _, err := database.Exec(`INSERT INTO blobs (v) VALUES (zeroblob(4096))`); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	grown := queryInt(t, database, "PRAGMA page_count;")
	if _, err := database.Exec(`DELETE FROM blobs`); err != nil {
		t.Fatalf("delete: %v", err)
	}

	store := &pathStatsStore{db: database, dialect: dialect}
	store.reclaimSQLDisk(context.Background())

	// Root cause #2, asserted: after the real reclaim path the pages are gone,
	// not merely marked free. Under either unfixed defect this stays at `grown`.
	after := queryInt(t, database, "PRAGMA page_count;")
	if after >= grown {
		t.Fatalf("reclaimSQLDisk freed nothing: page_count was %d after inserts, %d after delete+reclaim", grown, after)
	}
	if free := queryInt(t, database, "PRAGMA freelist_count;"); free != 0 {
		t.Fatalf("freelist_count=%d after reclaim, want 0 (pages were not returned to the OS)", free)
	}
	// The reclaim should return the file to roughly its pre-growth size, not
	// shave a page off the end. 400 four-KiB blobs is ~400 pages; anything near
	// `grown` means reclaim did not really run.
	if after > grown/4 {
		t.Fatalf("reclaimSQLDisk reclaimed too little: page_count %d -> %d (expected a drop to near empty)", grown, after)
	}
}

func queryInt(t *testing.T, database *sql.DB, stmt string) int {
	t.Helper()
	var n int
	if err := database.QueryRow(stmt).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", stmt, err)
	}
	return n
}
