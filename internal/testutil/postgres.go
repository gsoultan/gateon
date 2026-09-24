// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package testutil

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"

	_ "github.com/lib/pq" // the driver the gateway's own Postgres stores use
)

// postgresTestLock is the advisory-lock key every Postgres-backed test in the
// module serialises on.
const postgresTestLock = 7313001

var pgLock struct {
	mu   sync.Mutex
	held int
	db   *sql.DB
	conn *sql.Conn
}

// PostgresDSN returns GATEON_TEST_POSTGRES_DSN and holds the module-wide
// Postgres test lock until t ends, or skips t, giving skipReason, when the
// variable is unset.
func PostgresDSN(t testing.TB, skipReason string) string {
	t.Helper()
	dsn := os.Getenv("GATEON_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GATEON_TEST_POSTGRES_DSN not set; " + skipReason)
	}
	LockPostgres(t, dsn)
	return dsn
}

// LockPostgres serialises the calling test against every other Postgres test
// in the module until t ends.
//
// go test runs packages in parallel, and all of them share the one database CI
// provides. internal/db's upgrade test drops and recreates the schema; running
// beside internal/auth's lockout test it removed the users table mid-test
// ("relation users does not exist") and deadlocked its own reset. A
// session-level advisory lock orders the packages without giving each its own
// database. It is counted per process, so a test that reaches this from a
// helper and again from a subtest does not wait on itself.
func LockPostgres(t testing.TB, dsn string) {
	t.Helper()
	pgLock.mu.Lock()
	defer pgLock.mu.Unlock()
	if pgLock.held == 0 {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("postgres test lock: %v", err)
		}
		conn, err := db.Conn(context.Background())
		if err != nil {
			_ = db.Close()
			t.Fatalf("postgres test lock: %v", err)
		}
		if _, err := conn.ExecContext(context.Background(), "SELECT pg_advisory_lock($1)", postgresTestLock); err != nil {
			_ = conn.Close()
			_ = db.Close()
			t.Fatalf("postgres test lock: %v", err)
		}
		pgLock.db, pgLock.conn = db, conn
	}
	pgLock.held++
	t.Cleanup(releasePostgresLock)
}

func releasePostgresLock() {
	pgLock.mu.Lock()
	defer pgLock.mu.Unlock()
	pgLock.held--
	if pgLock.held > 0 {
		return
	}
	_, _ = pgLock.conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", postgresTestLock)
	_ = pgLock.conn.Close()
	_ = pgLock.db.Close()
	pgLock.db, pgLock.conn = nil, nil
}
