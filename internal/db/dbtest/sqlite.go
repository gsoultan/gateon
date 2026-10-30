// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package dbtest hands tests a database with every migration already applied,
// without each test paying for running them.
//
// Running the migrations is most of what opening a store costs a test: on
// SQLite under -race it is over a second per database, because modernc's
// pure-Go SQLite is instrumented line by line, and internal/api opened one in
// nearly every test. Here they run once per test binary, into a template that
// each test gets a copy of — a file copy for SQLite, CREATE DATABASE ...
// TEMPLATE for Postgres. The code under test still runs db.Migrate on the
// copy, which finds every migration applied, so nothing about how a store opens
// is skipped. Tests that are about migrating keep opening an empty database.
//
// The migrations themselves are never edited for this: the template is built
// by db.Migrate, the same function a gateway runs at startup.
package dbtest

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
)

// sqliteTemplate is one migrated SQLite image, held in memory so that nothing
// outlives the test binary: the file it was built in is removed at once.
type sqliteTemplate struct {
	once  sync.Once
	image []byte
	err   error
}

var sqliteTemplates struct {
	mu     sync.Mutex
	byPrag map[string]*sqliteTemplate
}

// SQLite writes a migrated SQLite database to path and returns path. The file
// must not exist; its directory must. It is what db.Open and db.Migrate would
// leave on an empty file, so it is in WAL mode like every database a gateway
// opens.
func SQLite(tb testing.TB, path string) string {
	tb.Helper()
	return SQLiteWith(tb, path, "")
}

// SQLiteWith is SQLite for a store that runs pragmas on its file before it
// migrates, as the telemetry store does. Some settings are written into the
// file and some can only be changed before the first table exists, so a
// template built without them would not be the database that store creates.
// Each distinct pragmas string gets a template of its own.
func SQLiteWith(tb testing.TB, path, pragmas string) string {
	tb.Helper()
	tmpl := sqliteTemplateFor(pragmas)
	tmpl.once.Do(func() { tmpl.image, tmpl.err = buildSQLiteImage(pragmas) })
	if tmpl.err != nil {
		tb.Fatalf("build the migrated SQLite template: %v", tmpl.err)
	}
	// O_EXCL: a test that names a file it already made is a test that would
	// otherwise read a database it did not expect.
	// #nosec G304 -- path is the calling test's own, in its own temp dir.
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		tb.Fatalf("copy the migrated SQLite template: %v", err)
	}
	if _, err := out.Write(tmpl.image); err != nil {
		_ = out.Close()
		tb.Fatalf("copy the migrated SQLite template: %v", err)
	}
	if err := out.Close(); err != nil {
		tb.Fatalf("copy the migrated SQLite template: %v", err)
	}
	return path
}

func sqliteTemplateFor(pragmas string) *sqliteTemplate {
	sqliteTemplates.mu.Lock()
	defer sqliteTemplates.mu.Unlock()
	if sqliteTemplates.byPrag == nil {
		sqliteTemplates.byPrag = map[string]*sqliteTemplate{}
	}
	tmpl, ok := sqliteTemplates.byPrag[pragmas]
	if !ok {
		tmpl = &sqliteTemplate{}
		sqliteTemplates.byPrag[pragmas] = tmpl
	}
	return tmpl
}

func buildSQLiteImage(pragmas string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "gateon-dbtest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "template.db")
	database, dialect, err := db.Open("sqlite://" + path)
	if err != nil {
		return nil, err
	}
	if err := migrateSQLite(database, dialect, pragmas); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := database.Close(); err != nil {
		return nil, err
	}
	// #nosec G304 -- the template file in the temp dir made above.
	return os.ReadFile(path)
}

func migrateSQLite(database *sql.DB, dialect db.Dialect, pragmas string) error {
	if pragmas != "" {
		if _, err := database.Exec(pragmas); err != nil {
			return fmt.Errorf("pragmas: %w", err)
		}
	}
	if err := db.Migrate(database, dialect); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// Fold the WAL into the file, so the file alone is the whole database.
	if _, err := database.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	return nil
}
