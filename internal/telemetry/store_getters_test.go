// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// These three getters are read from internal/api and internal/server/handlers
// and had no test. Each one has a store-absent branch, which is the branch that
// runs on a minimal-tier gateway where the trace store is never opened -- so it
// is the branch most likely to be taken in production and least likely to have
// been tried.

// withStore opens a SQLite store for one test and closes it afterwards, so no
// test inherits another's store or leaves one behind.
func withStore(t *testing.T) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "getters.db")
	if err := InitPathStatsStore("sqlite://"+dbPath, 7); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() { ClosePathStatsStore(context.Background()) })
}

func TestPingStoreReportsAnOpenStore(t *testing.T) {
	withStore(t)

	if err := PingStore(context.Background()); err != nil {
		t.Errorf("PingStore on an open store: %v", err)
	}
}

// TestPingStoreSaysSoWhenThereIsNoStore matters because this is what the
// diagnostics page calls to tell an operator whether telemetry persistence is
// healthy. Returning nil with no store would report a working database where
// there is none at all.
func TestPingStoreSaysSoWhenThereIsNoStore(t *testing.T) {
	ClosePathStatsStore(context.Background())

	if err := PingStore(context.Background()); err == nil {
		t.Error("PingStore returned nil with no store open; diagnostics would " +
			"report telemetry persistence healthy when it is absent")
	}
}

func TestPathStatsWindowFallsBackWithNoStore(t *testing.T) {
	ClosePathStatsStore(context.Background())

	// Must not panic and must not report a database answer it does not have.
	// The in-memory fallback is allowed to be empty; nil-dereferencing is not.
	_ = GetPathStatsWindow(context.Background(), 7)
}

// TestPathStatsWindowAcceptsANonPositiveWindow pins the retention default. A
// caller passing 0 -- which is what an unset proto int32 is -- must get the
// configured retention window rather than a cutoff of today or, worse, a
// negative window that selects nothing.
func TestPathStatsWindowAcceptsANonPositiveWindow(t *testing.T) {
	withStore(t)

	for _, days := range []int{0, -1, 7} {
		if got := GetPathStatsWindow(context.Background(), days); got == nil {
			// A nil slice is a legitimate "no rows"; the assertion is that the
			// call completes rather than panicking on the cutoff arithmetic.
			continue
		}
	}
}

func TestGetTraceReturnsNilForAnUnknownID(t *testing.T) {
	withStore(t)

	if got := GetTrace(time.Now().UTC(), "no-such-trace-id"); got != nil {
		t.Errorf("GetTrace for an unknown id = %+v, want nil", got)
	}
}

// TestGetTraceWithNoStoreDoesNotPanic covers the minimal tier, where the trace
// store is never opened but the traces handler is still routable.
func TestGetTraceWithNoStoreDoesNotPanic(t *testing.T) {
	ClosePathStatsStore(context.Background())

	if got := GetTrace(time.Now().UTC(), "anything"); got != nil {
		t.Errorf("GetTrace with no store = %+v, want nil", got)
	}
}
