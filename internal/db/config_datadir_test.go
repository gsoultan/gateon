// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"os"
	"path/filepath"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestResolveSQLitePath: a relative SQLite file goes into the data directory;
// everything that is not one -- a server URL, an absolute path, an in-memory
// database, a file: URI -- is left exactly as written.
func TestResolveSQLitePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	cases := []struct{ in, want string }{
		{"gateon.db", filepath.Join(dir, "gateon.db")},
		{"sqlite:gateon.db", "sqlite:" + filepath.Join(dir, "gateon.db")},
		{"sqlite://sub/gateon.db", "sqlite://" + filepath.Join(dir, "sub", "gateon.db")},
		{"/abs/gateon.db", "/abs/gateon.db"},
		{"sqlite:///abs/gateon.db", "sqlite:///abs/gateon.db"},
		{":memory:", ":memory:"},
		{"sqlite::memory:", "sqlite::memory:"},
		{"file:gateon.db?mode=ro", "file:gateon.db?mode=ro"},
		{"postgres://u:p@h:5432/gateon", "postgres://u:p@h:5432/gateon"},
		{"", ""},
	}
	for _, c := range cases {
		if got := ResolveSQLitePath(c.in, dir); got != c.want {
			t.Errorf("ResolveSQLitePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAuthDatabaseURLIsInTheDataDirectory: every way the config names a
// relative SQLite file -- the default, sqlite_path, database_url and
// database_config -- resolves inside GATEON_DATA_DIR, not the working
// directory the process happened to start in.
func TestAuthDatabaseURLIsInTheDataDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GATEON_DATA_DIR", dir)
	want := filepath.Join(dir, "gateon.db")
	for name, a := range map[string]*gateonv1.AuthConfig{
		"default":         nil,
		"sqlite_path":     {SqlitePath: "gateon.db"},
		"database_url":    {DatabaseUrl: "gateon.db"},
		"database_config": {DatabaseConfig: &gateonv1.DatabaseConfig{Driver: "sqlite", SqlitePath: "gateon.db"}},
	} {
		if got := AuthDatabaseURL(a); got != want {
			t.Errorf("%s: AuthDatabaseURL = %q, want %q", name, got, want)
		}
	}
	if got := AuditDatabaseURL(&gateonv1.AuditConfig{DatabaseUrl: "logs.db"}, nil); got != filepath.Join(dir, "logs.db") {
		t.Errorf("audit database_url = %q, want it in the data directory", got)
	}
}

// TestProbeJudgesTheFileTheGatewayOpens: the wizard's connection test resolved
// a relative SQLite path against the working directory while the gateway opens
// it in the data directory, so it could pass for one file and set up another.
func TestProbeJudgesTheFileTheGatewayOpens(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	t.Chdir(elsewhere)
	if err := Probe("probe.db", nil, dir); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "probe.db")); err != nil {
		t.Errorf("the probe did not open the file in the data directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "probe.db")); err == nil {
		t.Error("the probe opened a file in the working directory")
	}
}

// TestSQLiteFile names the file a SQLite URL opens, and nothing for the rest.
func TestSQLiteFile(t *testing.T) {
	for in, want := range map[string]string{
		"/d/gateon.db": "/d/gateon.db", "sqlite:/d/g.db": "/d/g.db", "sqlite:///d/g.db": "/d/g.db",
		":memory:": "", "file:x.db": "", "postgres://h/db": "",
	} {
		got, ok := SQLiteFile(in)
		if got != want || ok != (want != "") {
			t.Errorf("SQLiteFile(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}
