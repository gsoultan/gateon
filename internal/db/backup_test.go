// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// observed records what a migration told its observer.
type observed struct {
	begun, ended []MigrationRun
	// backupAtBegin: the copy existed when Begin was called. It must not:
	// Begin is what tells the upgrade helper to wait for the copy.
	backupAtBegin bool
}

func (o *observed) Begin(run MigrationRun) {
	o.begun = append(o.begun, run)
	if run.Backup != "" {
		_, err := os.Stat(run.Backup)
		o.backupAtBegin = err == nil
	}
}
func (o *observed) End(run MigrationRun) { o.ended = append(o.ended, run) }

// observe installs an observer for one test.
func observe(t *testing.T) *observed {
	t.Helper()
	o := &observed{}
	SetMigrationObserver(o)
	t.Cleanup(func() { migrationObserver.Store(nil) })
	return o
}

// openAt opens a SQLite database at an earlier release's schema, holding
// one row a later check can look for.
func openAt(t *testing.T, last int) (*sql.DB, Dialect, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateon.db")
	database, dialect, err := Open("sqlite:" + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if last > 0 {
		if err := migrateUpTo(database, dialect, last); err != nil {
			t.Fatal(err)
		}
	}
	return database, dialect, path
}

// lastMigration is the newest migration this build registers.
func lastMigration(t *testing.T, database *sql.DB) int {
	t.Helper()
	var id int
	if err := database.QueryRow("SELECT MAX(id) FROM migrations").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAnExistingSQLiteDatabaseIsCopiedAsideBeforeItIsMigrated(t *testing.T) {
	o := observe(t)
	const from = 62
	database, dialect, path := openAt(t, from)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	backup := path + BackupSuffix
	copyDB, _, err := Open("sqlite:" + backup)
	if err != nil {
		t.Fatalf("the copy cannot be opened: %v", err)
	}
	defer func() { _ = copyDB.Close() }()
	if got := lastMigration(t, copyDB); got != from {
		t.Fatalf("the copy is at migration %d, want the %d it was taken at: it was taken after migrating", got, from)
	}
	if got := lastMigration(t, database); got <= from {
		t.Fatalf("the database itself was not migrated past %d", got)
	}
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the copy holds credentials and is not 0600: %v %v", info.Mode().Perm(), err)
	}
	want := MigrationRun{Driver: DriverSQLite, Database: path, Backup: backup}
	if len(o.begun) != 1 || len(o.ended) != 1 || o.begun[0] != want || o.ended[0] != want {
		t.Fatalf("observer saw begin %+v end %+v, want one %+v each", o.begun, o.ended, want)
	}
	if o.backupAtBegin {
		t.Fatal("the observer was told after the copy was made; the helper would not know to wait for it")
	}
}

func TestAFreshDatabaseIsNotCopiedOrReported(t *testing.T) {
	o := observe(t)
	database, dialect, path := openAt(t, 0)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + BackupSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a database with nothing in it was copied aside: %v", err)
	}
	if len(o.begun)+len(o.ended) != 0 {
		t.Fatalf("a first install was reported as an upgrade: %+v", o.begun)
	}
}

func TestAnUpToDateDatabaseIsNotCopiedAgain(t *testing.T) {
	database, dialect, path := openAt(t, 62)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + BackupSuffix); err != nil {
		t.Fatal(err)
	}
	o := observe(t)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + BackupSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a start with nothing to migrate copied the database")
	}
	if len(o.begun) != 0 {
		t.Fatalf("a start with nothing to migrate was reported: %+v", o.begun)
	}
}

func TestTheCopyCanBeSwitchedOffAndTheObserverIsToldThereIsNone(t *testing.T) {
	t.Setenv(EnvMigrationBackup, "0")
	o := observe(t)
	database, dialect, path := openAt(t, 62)
	if err := Migrate(database, dialect); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + BackupSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the database was copied with the copy switched off")
	}
	if len(o.begun) != 1 || o.begun[0].Backup != "" || o.begun[0].Database != path {
		t.Fatalf("observer saw %+v, want one run with no backup", o.begun)
	}
}

func TestAMigrationDoesNotRunWhenItsCopyCannotBeMade(t *testing.T) {
	const from = 62
	database, dialect, path := openAt(t, from)
	// A directory where the copy goes: it can be neither removed nor written.
	if err := os.MkdirAll(filepath.Join(path+BackupSuffix, "in-the-way"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(database, dialect); err == nil {
		t.Fatal("the database was migrated though no copy of it could be made")
	}
	if got := lastMigration(t, database); got != from {
		t.Fatalf("migration %d ran without a copy to go back to", got)
	}
}
