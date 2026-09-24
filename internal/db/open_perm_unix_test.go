// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package db

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// withUmask022 pins the process umask to the common default for one test.
//
// The defect only shows under a permissive umask: SQLite creates its files
// 0644 and relies on the umask to take bits away, so on a host whose umask is
// already 077 an unfixed Open produces 0600 and these tests would pass for the
// wrong reason. 022 is what systemd, Docker and a login shell all hand a
// process unless told otherwise. The umask is process-wide, which is why none
// of these tests is parallel.
func withUmask022(t *testing.T) {
	t.Helper()
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

// assertOwnerOnly fails when path grants any access to group or other.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("%s has mode %#o; the management database holds middleware "+
			"secrets (JWT/HMAC keys, OIDC client secrets, API keys), password "+
			"hashes and the audit trail, so it must not be readable by other "+
			"local accounts", filepath.Base(path), perm)
	}
}

// TestOpenCreatesSQLiteFilesOwnerOnly is the fresh-install case. SQLite creates
// the database with its compiled-in default of 0644, and the WAL and shared-
// memory files inherit the database file's mode, so every file of a new
// install was world-readable. Under the packaged systemd unit /var/lib/gateon
// is 0755, which left nothing between any local account and those files.
func TestOpenCreatesSQLiteFilesOwnerOnly(t *testing.T) {
	withUmask022(t)
	path := filepath.Join(t.TempDir(), "gateon.db")

	conn, _, err := Open("sqlite:" + path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// A write is what makes SQLite create the -wal and -shm files; the
	// connection stays open so they still exist when they are checked.
	if _, err := conn.Exec("CREATE TABLE probe (x INTEGER)"); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		assertOwnerOnly(t, p)
	}
}

// TestOpenTightensAnExistingWorldReadableDatabase is the upgrade case: an
// install that already has a 0644 database, and a stale 0644 WAL left behind
// by an unclean shutdown, must not stay readable just because the files were
// created by an earlier version.
//
// The stale WAL has to carry frames. SQLite fchmods a sidecar it opens only
// when the file is empty, so an empty stand-in is repaired by SQLite itself
// and cannot tell whether Open tightened it; a WAL that survived a crash is
// not empty, and SQLite leaves its mode alone.
func TestOpenTightensAnExistingWorldReadableDatabase(t *testing.T) {
	withUmask022(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "gateon.db")
	stale := path + "-wal"

	seed, _, err := Open("sqlite:" + path)
	if err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	if _, err := seed.Exec("CREATE TABLE probe (x INTEGER)"); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	// Keep the WAL as a crash would have left it: the clean Close below
	// checkpoints and deletes it.
	frames, err := os.ReadFile(stale)
	if err != nil || len(frames) == 0 {
		t.Fatalf("seed wal not captured (len %d): %v", len(frames), err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("seed Close: %v", err)
	}
	// Recreate what an earlier version left on disk.
	if err := os.WriteFile(stale, frames, 0o600); err != nil {
		t.Fatalf("seed stale wal: %v", err)
	}
	for _, p := range []string{path, stale} {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatalf("loosen %s: %v", p, err)
		}
	}

	conn, _, err := Open("sqlite:" + path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	for _, p := range []string{path, stale} {
		assertOwnerOnly(t, p)
	}
}

// TestOpenLeavesInMemoryDatabasesAlone guards the fix against touching the
// filesystem for a database that has no file: ":memory:" must not become a
// file of that name in the working directory.
func TestOpenLeavesInMemoryDatabasesAlone(t *testing.T) {
	withUmask022(t)
	t.Chdir(t.TempDir())

	conn, _, err := Open("sqlite::memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := os.Stat(":memory:"); !os.IsNotExist(err) {
		t.Fatalf("an in-memory database created a file on disk (stat err = %v)", err)
	}
}
