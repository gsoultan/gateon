// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"os"
	"testing"

	"github.com/gsoultan/gateon/internal/db/dbtest"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestMain runs the package through dbtest, which drops the migrated Postgres
// template once every test has had its copy.
//
// Nearly every test here opens a telemetry or auth store, and opening one on a
// new file ran all seventy migrations again: two thirds of the package's time
// under -race, and enough to push go test past its ten-minute default. They
// open a copy of a migrated template instead (see dbtest). Tests about what
// Setup does to a database it chose still start from an empty one.
func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }

// telemetryDB writes a migrated telemetry database to path and returns path,
// for InitPathStatsStore. Built with the store's own pragmas, since
// auto_vacuum only takes effect on an empty file.
func telemetryDB(t *testing.T, path string) string {
	t.Helper()
	return dbtest.SQLiteWith(t, path, telemetry.SQLitePragmas)
}
