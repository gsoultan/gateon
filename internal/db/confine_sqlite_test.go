// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"errors"
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
