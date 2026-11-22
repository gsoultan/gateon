// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package testutil

import "testing"

// A test that needs a pooler skips without one, and is handed the pooler's DSN
// with one. With no direct DSN there is no lock to take, so this needs no
// database.
func TestPgBouncerDSN(t *testing.T) {
	t.Setenv("GATEON_TEST_POSTGRES_DSN", "")

	t.Setenv("GATEON_TEST_PGBOUNCER_DSN", "")
	var reached bool
	t.Run("unset", func(t *testing.T) {
		PgBouncerDSN(t, "no pooler here")
		reached = true
	})
	if reached {
		t.Error("PgBouncerDSN returned without a DSN instead of skipping")
	}

	const dsn = "postgres://u:p@127.0.0.1:6432/d?sslmode=disable"
	t.Setenv("GATEON_TEST_PGBOUNCER_DSN", dsn)
	if got := PgBouncerDSN(t, "unused"); got != dsn {
		t.Errorf("PgBouncerDSN = %q, want %q", got, dsn)
	}
}
