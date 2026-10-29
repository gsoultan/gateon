// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gsoultan/gateon/internal/db"
)

// Most tests here open the store on a new SQLite file, and opening it ran
// every migration again: about 1.4 s of each test under -race, two thirds of
// the package's time. A -race pass took four and a half minutes, so
// `go test -race -count=3` ran past the default ten-minute timeout and looked
// like a hang. The migrations are run once per test binary instead, into a
// template that each test copies. InitPathStatsStore still runs db.Migrate on
// the copy, which finds every migration applied; the tests that are about
// migrating keep opening an empty file.

var migratedTemplate struct {
	once sync.Once
	dir  string
	path string
	err  error
}

// TestMain removes the template once every test has had it.
func TestMain(m *testing.M) {
	code := m.Run()
	if migratedTemplate.dir != "" {
		_ = os.RemoveAll(migratedTemplate.dir)
	}
	os.Exit(code)
}

// migratedSQLite returns the path of a new SQLite database named name in tb's
// temp dir, with every migration already applied.
func migratedSQLite(tb testing.TB, name string) string {
	tb.Helper()
	migratedTemplate.once.Do(buildMigratedTemplate)
	if migratedTemplate.err != nil {
		tb.Fatalf("build the migrated SQLite template: %v", migratedTemplate.err)
	}
	dst := filepath.Join(tb.TempDir(), name)
	if err := copyFile(migratedTemplate.path, dst); err != nil {
		tb.Fatalf("copy the migrated SQLite template: %v", err)
	}
	return dst
}

func buildMigratedTemplate() {
	t := &migratedTemplate
	if t.dir, t.err = os.MkdirTemp("", "gateon-telemetry-template-"); t.err != nil {
		return
	}
	t.path = filepath.Join(t.dir, "template.db")
	database, dialect, err := db.Open("sqlite://" + t.path)
	if err != nil {
		t.err = err
		return
	}
	defer database.Close()
	if _, err := database.Exec(SQLitePragmas); err != nil {
		t.err = fmt.Errorf("pragmas: %w", err)
		return
	}
	if err := db.Migrate(database, dialect); err != nil {
		t.err = fmt.Errorf("migrate: %w", err)
		return
	}
	// Fold the WAL into the file, so the file alone is the whole database.
	if _, err := database.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		t.err = fmt.Errorf("checkpoint: %w", err)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
