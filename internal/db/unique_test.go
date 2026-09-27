// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/testutil"
)

// TestIsUniqueViolation: a duplicate unique column and a duplicate primary key
// are both reported, on both engines, and a NOT NULL failure -- another
// constraint, not a duplicate -- is not.
func TestIsUniqueViolation(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		database, _, err := Open("sqlite:" + filepath.Join(t.TempDir(), "unique.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = database.Close() })
		conn, err := database.Conn(t.Context())
		if err != nil {
			t.Fatalf("conn: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		assertUniqueViolations(t, conn, "?")
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := testutil.PostgresDSN(t, "the Postgres half of the classifier")
		database, _, err := Open(dsn)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = database.Close() })
		// One connection throughout: the table is TEMP, so it lives and dies
		// with this session and nothing in the shared database changes.
		conn, err := database.Conn(t.Context())
		if err != nil {
			t.Fatalf("conn: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		assertUniqueViolations(t, conn, "$")
	})
	if IsUniqueViolation(nil) || IsUniqueViolation(errors.New("UNIQUE constraint failed")) {
		t.Error("an error that did not come from a database was reported as a duplicate")
	}
}

func assertUniqueViolations(t *testing.T, conn *sql.Conn, placeholder string) {
	t.Helper()
	ctx := t.Context()
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE unique_probe (
		id VARCHAR(64) PRIMARY KEY, name VARCHAR(64) UNIQUE NOT NULL)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	insert := "INSERT INTO unique_probe (id, name) VALUES (?, ?)"
	if placeholder == "$" {
		insert = "INSERT INTO unique_probe (id, name) VALUES ($1, $2)"
	}
	if _, err := conn.ExecContext(ctx, insert, "a", "alice"); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	for name, c := range map[string]struct {
		args []any
		want bool
	}{
		"a taken unique column": {[]any{"b", "alice"}, true},
		"a taken primary key":   {[]any{"a", "bob"}, true},
		"a NOT NULL failure":    {[]any{"c", nil}, false},
	} {
		_, err := conn.ExecContext(ctx, insert, c.args...)
		if err == nil {
			t.Fatalf("%s: the insert succeeded", name)
		}
		if got := IsUniqueViolation(err); got != c.want {
			t.Errorf("%s: IsUniqueViolation(%v) = %v, want %v", name, err, got, c.want)
		}
	}
}
