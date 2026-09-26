// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ConfineSQLite admits a plain file path in the data directory and nothing
// else a SQLite url can say. Each refusal below is a way the file the driver
// opens differs from the path a check on the string sees.
func TestConfineSQLite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // relative paths resolve as the opener resolves them
	inside := filepath.Join(dir, "gateon.db")
	// Cleaned, this is inside dir; C reads it only as far as the NUL.
	nul := "/etc/passwd\x00" + strings.Repeat("/..", 2) + dir + "/gateon.db"

	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"gateon.db", true},
		{"sub/gateon.db", true},
		{"sqlite:gateon.db", true},
		{"sqlite://" + inside, true},
		{"sqlite:", true}, // the opener's default, gateon.db
		{"sqlite::memory:", true},
		{"postgres://gateon:secret@127.0.0.1:5432/gateon", true}, // not SQLite's to judge

		{"../gateon.db", false},
		{"/etc/passwd", false},
		{"//etc/passwd", false},
		{"sqlite://" + dir + "/../gateon.db", false},
		{inside + "?mode=rwc", false},
		{"sqlite://" + inside + "?_pragma=foreign_keys(1)", false},
		{"file:" + inside, false},
		{"FILE:" + inside, false},
		{"sqlite:file:" + inside, false},
		{nul, false},
	} {
		err := ConfineSQLite(tc.url, dir)
		if got := err == nil; got != tc.want {
			t.Errorf("ConfineSQLite(%q) admitted=%v, want %v (err %v)", tc.url, got, tc.want, err)
		}
		if err != nil && !errors.Is(err, ErrSQLiteNotConfined) {
			t.Errorf("ConfineSQLite(%q) = %v, want ErrSQLiteNotConfined", tc.url, err)
		}
	}
}

// ConfineSQLite compares where the paths are, not how they are written. Abs
// resolves a relative path against Getwd, which answers with the directory
// symlinks resolve to; the data directory is named as configured. So a data
// directory reached through a symlink refused every relative path, the wizard's
// default gateon.db among them -- found by the first-run e2e spec, whose temp
// directory sits under macOS's /var -> /private/var. The same comparison let a
// symlink inside the directory lead out of it.
func TestConfineSQLiteComparesWhereThePathsAre(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Chdir(real) // where a process in the linked directory finds itself
	if err := ConfineSQLite("gateon.db", link); err != nil {
		t.Errorf("a relative path in a data directory named through a symlink was refused: %v", err)
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(real, "out")); err != nil {
		t.Fatal(err)
	}
	if err := ConfineSQLite(filepath.Join(real, "out", "escape.db"), real); !errors.Is(err, ErrSQLiteNotConfined) {
		t.Errorf("a path through a symlink out of the data directory = %v, want ErrSQLiteNotConfined", err)
	}
}
