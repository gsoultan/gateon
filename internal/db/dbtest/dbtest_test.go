// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package dbtest

import (
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
)

func TestMain(m *testing.M) { os.Exit(Run(m)) }

// A template is only a shortcut if it is the database the migrations would
// have built. Each test here builds one the slow way and compares.

func TestSQLiteIsWhatMigratingAnEmptyFileBuilds(t *testing.T) {
	dir := t.TempDir()
	want := openSQLite(t, filepath.Join(dir, "fresh.db"), "")
	got := openSQLite(t, SQLite(t, filepath.Join(dir, "copy.db")), "")
	assertSameDatabase(t, want, got)
	if mode := pragma(t, got, "journal_mode"); mode != "wal" {
		t.Errorf("journal_mode = %q, want wal like every database db.Open opens", mode)
	}
}

// SQLiteWith builds its template the way the store it stands in for builds
// its file: the pragmas first, then the migrations. user_version stands in for
// any setting that is written into the file, since it always is.
func TestSQLiteWithRunsThePragmasBeforeMigrating(t *testing.T) {
	const pragmas = "PRAGMA auto_vacuum=INCREMENTAL; PRAGMA user_version=7;"
	dir := t.TempDir()
	want := openSQLite(t, filepath.Join(dir, "fresh.db"), pragmas)
	got := openSQLite(t, SQLiteWith(t, filepath.Join(dir, "copy.db"), pragmas), "")
	assertSameDatabase(t, want, got)
	for _, name := range []string{"user_version", "auto_vacuum", "journal_mode"} {
		if w, g := pragma(t, want, name), pragma(t, got, name); w != g {
			t.Errorf("%s = %q on the copy, %q on a freshly migrated file", name, g, w)
		}
	}
	if v := pragma(t, got, "user_version"); v != "7" {
		t.Errorf("user_version = %q on the copy, want 7", v)
	}
	if v := pragma(t, openSQLite(t, SQLite(t, filepath.Join(dir, "plain.db")), ""), "user_version"); v != "0" {
		t.Errorf("user_version = %q on a template built without the pragmas, want 0", v)
	}
}

// Each copy is a database of its own: a write to one is not seen by the next.
func TestSQLiteCopiesDoNotShareRows(t *testing.T) {
	dir := t.TempDir()
	first := openSQLite(t, SQLite(t, filepath.Join(dir, "a.db")), "")
	if _, err := first.Exec("INSERT INTO users (id, username, password, role) VALUES ('u', 'u', 'p', 'admin')"); err != nil {
		t.Fatal(err)
	}
	second := openSQLite(t, SQLite(t, filepath.Join(dir, "b.db")), "")
	var n int
	if err := second.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); err != nil || n != 0 {
		t.Errorf("a new copy holds %d users (err %v), want 0", n, err)
	}
}

func TestPostgresIsWhatMigratingAnEmptyDatabaseBuilds(t *testing.T) {
	got, dialect, err := db.Open(Postgres(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = got.Close() })
	applied := appliedMigrations(t, got)
	if err := db.Migrate(got, dialect); err != nil {
		t.Fatalf("migrate the copy: %v", err)
	}
	if after := appliedMigrations(t, got); !slices.Equal(applied, after) {
		t.Errorf("migrating the copy applied %d more migrations; the template was not fully migrated",
			len(after)-len(applied))
	}
	if !db.TableExists(got, dialect, "users") {
		t.Error("the copy has no users table")
	}
}

// openSQLite opens path, first migrating it after pragmas when it does not
// exist yet: the slow way, for comparison. It calls db.Migrate itself rather
// than sharing migrateSQLite, or a template that skipped a step would be
// compared against a database that skipped the same one.
func openSQLite(t *testing.T, path, pragmas string) *sql.DB {
	t.Helper()
	_, statErr := os.Stat(path)
	database, dialect, err := db.Open("sqlite://" + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if !os.IsNotExist(statErr) {
		return database
	}
	if pragmas != "" {
		if _, err := database.Exec(pragmas); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	return database
}

func assertSameDatabase(t *testing.T, want, got *sql.DB) {
	t.Helper()
	if w, g := schema(t, want), schema(t, got); !slices.Equal(w, g) {
		t.Errorf("schema differs from a freshly migrated file:\nwant %q\ngot  %q", w, g)
	}
	if w, g := appliedMigrations(t, want), appliedMigrations(t, got); !slices.Equal(w, g) {
		t.Errorf("applied migrations = %v, want %v", g, w)
	}
}

func schema(t *testing.T, database *sql.DB) []string {
	t.Helper()
	return column(t, database, "SELECT type || ' ' || name || ' ' || COALESCE(sql, '') FROM sqlite_master ORDER BY type, name")
}

func appliedMigrations(t *testing.T, database *sql.DB) []string {
	t.Helper()
	return column(t, database, "SELECT CAST(id AS TEXT) || ' ' || name FROM migrations ORDER BY id")
}

func pragma(t *testing.T, database *sql.DB, name string) string {
	t.Helper()
	var v string
	if err := database.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	return v
}

func column(t *testing.T, database *sql.DB, query string) []string {
	t.Helper()
	rows, err := database.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("%s returned nothing", query)
	}
	return out
}
