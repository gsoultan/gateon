// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveTraceDir_NonSQLiteHonoursDataDir pins the fix for a Postgres-backed
// gateway writing its Pebble trace store into whatever directory it was started
// from. A relative path is not merely untidy: the same binary then keeps trace
// data in a different place under systemd, in a container and on a developer's
// machine, and an operator who set GATEON_DATA_DIR does not get told it was
// ignored.
func TestResolveTraceDir_NonSQLiteHonoursDataDir(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dataDir)
	t.Setenv("GATEON_TRACE_DIR", "")

	got := resolveTraceDir("postgres://user:pass@localhost:5432/gateon", false)

	want := filepath.Join(dataDir, "telemetry_pebble")
	if got != want {
		t.Fatalf("resolveTraceDir = %q, want %q", got, want)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("resolveTraceDir returned the relative path %q; it resolves against "+
			"the process working directory, which differs per deployment", got)
	}
}

// GATEON_TRACE_DIR is the operator's outright override and must still win over
// the data directory.
func TestResolveTraceDir_TraceDirOverridesDataDir(t *testing.T) {
	explicit := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", t.TempDir())
	t.Setenv("GATEON_TRACE_DIR", explicit)

	if got := resolveTraceDir("postgres://localhost/gateon", false); got != explicit {
		t.Fatalf("resolveTraceDir = %q, want the explicit override %q", got, explicit)
	}
}

// A file-backed SQLite DB keeps its traces beside the database, which is
// deliberate and unchanged: the two belong together and move together.
func TestResolveTraceDir_SQLiteSitsBesideTheDatabase(t *testing.T) {
	dbDir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", t.TempDir())
	t.Setenv("GATEON_TRACE_DIR", "")

	dsn := filepath.Join(dbDir, "gateon.db")
	want := filepath.Join(dbDir, "telemetry_pebble")

	if got := resolveTraceDir("sqlite:"+dsn, true); got != want {
		t.Fatalf("resolveTraceDir = %q, want %q", got, want)
	}
}

// An in-memory DSN is ephemeral, so its traces go to a temp dir rather than
// outliving the database in the working directory.
func TestResolveTraceDir_InMemoryUsesTempDir(t *testing.T) {
	t.Setenv("GATEON_DATA_DIR", t.TempDir())
	t.Setenv("GATEON_TRACE_DIR", "")

	got := resolveTraceDir("sqlite::memory:", true)

	if want := filepath.Join(os.TempDir(), "gateon-telemetry-pebble"); got != want {
		t.Fatalf("resolveTraceDir = %q, want %q", got, want)
	}
}
