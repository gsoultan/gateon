// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/db/dbtest"
)

// Most tests here open the store on a new SQLite file, and opening it ran
// every migration again: about 1.4 s of each test under -race, two thirds of
// the package's time. A -race pass took four and a half minutes, so
// `go test -race -count=3` ran past the default ten-minute timeout and looked
// like a hang. The migrations are run once per test binary instead, into a
// template that each test copies (dbtest). InitPathStatsStore still runs
// db.Migrate on the copy, which finds every migration applied; the tests that
// are about migrating keep opening an empty file.

// migratedSQLite returns the path of a new SQLite database named name in tb's
// temp dir, with every migration already applied.
func migratedSQLite(tb testing.TB, name string) string {
	tb.Helper()
	return dbtest.SQLiteWith(tb, filepath.Join(tb.TempDir(), name), SQLitePragmas)
}
