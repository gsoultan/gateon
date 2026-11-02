// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package db

import (
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/testutil"
)

// Every store's pool was sized for Postgres whatever the engine: on SQLite,
// four stores at standard's 25 connections could pin 800 MiB of page cache
// and queued a hundred connections on one write lock. On SQLite the pool is
// now the tier's SQLiteMaxOpenConns; Postgres keeps DBMaxOpenConns.
func TestSQLitePoolsAreSizedForOneWriter(t *testing.T) {
	t.Setenv("GATEON_PROFILE", string(config.TierStandard))
	td := config.DefaultsFor(config.TierStandard)
	if td.SQLiteMaxOpenConns >= td.DBMaxOpenConns {
		t.Fatalf("standard's SQLite pool (%d) is not smaller than its Postgres pool (%d)", td.SQLiteMaxOpenConns, td.DBMaxOpenConns)
	}
	conn, _, err := Open("sqlite://" + filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if got := conn.Stats().MaxOpenConnections; got != td.SQLiteMaxOpenConns {
		t.Fatalf("SQLite pool holds %d connections, want the tier's %d", got, td.SQLiteMaxOpenConns)
	}

	t.Run("postgres keeps its size", func(t *testing.T) {
		pg, _, err := Open(testutil.PostgresDSN(t, "skipping the Postgres run"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pg.Close() })
		if got := pg.Stats().MaxOpenConnections; got != td.DBMaxOpenConns {
			t.Fatalf("Postgres pool holds %d connections, want %d", got, td.DBMaxOpenConns)
		}
	})
	t.Run("env overrides", func(t *testing.T) {
		t.Setenv(EnvSQLiteMaxOpenConns, "7")
		if open, idle := PoolLimits(DriverSQLite, td); open != 7 || idle != 7 {
			t.Fatalf("PoolLimits = %d/%d with %s=7", open, idle, EnvSQLiteMaxOpenConns)
		}
		t.Setenv(EnvSQLiteMaxOpenConns, "none")
		if open, _ := PoolLimits(DriverSQLite, td); open != td.SQLiteMaxOpenConns {
			t.Fatalf("a malformed %s changed the pool to %d", EnvSQLiteMaxOpenConns, open)
		}
	})
}
