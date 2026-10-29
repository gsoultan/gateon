// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import "testing"

// IPShunMinClasses is the escalation's bar, for the tests in telemetry_test
// that drive an address to a shun through the recording path.
const IPShunMinClasses = ipShunMinClasses

// MigratedSQLite is migratedSQLite, for the tests in telemetry_test.
func MigratedSQLite(tb testing.TB, name string) string { return migratedSQLite(tb, name) }
