// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"testing"
)

// freshStore points the process-global path-stats store at a database of this
// test's own, and closes it afterwards.
//
// The closing half is the part that matters. InitPathStatsStore returns nil --
// success -- without doing anything when a store is already open:
//
//	if store != nil {
//		return nil
//	}
//
// So a test that opens its own t.TempDir() database while a previous test's
// store is still open gets a silent no-op: it writes and reads against the
// earlier database while its own file sits empty, and whether its assertions
// hold depends on which test ran first. Checking the error does not help,
// because there is no error.
//
// That is what made internal/telemetry fail under -shuffle=on across four
// different tests in user_mitigation_test.go and never in CI's declaration
// order. Closing first makes the Init real.
func freshStore(t *testing.T) {
	t.Helper()
	ClosePathStatsStore(context.Background())

	dbPath := filepath.Join(t.TempDir(), "telemetry_test.db")
	if err := InitPathStatsStore(dbPath, 1); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { ClosePathStatsStore(context.Background()) })
}
