// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
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
	t.Cleanup(func() { withStore(t) })

	if err := PingStore(context.Background()); err == nil {
		t.Error("PingStore returned nil with no store open; diagnostics would " +
			"report telemetry persistence healthy when it is absent")
	}
}

// TestPathStatsWindowFallsBackToMemoryWithNoStore covers the minimal tier,
// where the store is never opened but the handler is still routable.
//
// The fallback is in-memory and legitimately returns rows -- an earlier version
// of this test asserted it must be empty and failed, which is how I learned
// that. What matters is that closing the database does not blank the
// diagnostics page: a request recorded while there is no store must still come
// back.
func TestPathStatsWindowFallsBackToMemoryWithNoStore(t *testing.T) {
	ClosePathStatsStore(context.Background())
	t.Cleanup(func() { withStore(t) })

	const path = "/fallback-probe"
	RecordPathRequest("example.test", path, 0.01, 512)

	got := GetPathStatsWindow(context.Background(), 7)
	for _, row := range got {
		if strings.Contains(row.Path, path) {
			return
		}
	}
	t.Errorf("a request recorded with no store did not come back from the "+
		"in-memory fallback (%d rows returned); on a minimal-tier gateway the "+
		"diagnostics page would be permanently empty", len(got))
}

// TestPathStatsWindowAppliesTheRetentionDefault pins what the old version of
// this test claimed to and did not. It looped over three window sizes with
// `if got == nil { continue }` and nothing after the if, so no assertion ran on
// either branch: deleting the retention default outright left it passing.
//
// A caller passing 0 -- which is what an unset proto int32 is -- must get the
// configured retention window. The check is that 0 behaves like the configured
// value and unlike a cutoff of today, which is the mistake a missing default
// actually produces.
func TestPathStatsWindowAppliesTheRetentionDefault(t *testing.T) {
	withStore(t)

	const path = "/retention-probe"
	RecordPathRequest("example.test", path, 0.01, 256)

	// Path stats are buffered and flushed on an interval, like traces, so this
	// polls. Asserting real rows -- rather than only comparing two calls -- is
	// the part that matters: a comparison is satisfied by a function that
	// always returns nothing, which is what the first version could not tell
	// apart from a working retention default.
	var zero []PathStats
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		zero = GetPathStatsWindow(context.Background(), 0)
		if slices.ContainsFunc(zero, func(r PathStats) bool {
			return strings.Contains(r.Path, path)
		}) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !slices.ContainsFunc(zero, func(r PathStats) bool {
		return strings.Contains(r.Path, path)
	}) {
		t.Fatalf("GetPathStatsWindow(0) returned %d rows after 15s and none "+
			"was the request just recorded; an unset window is selecting "+
			"nothing rather than falling back to the configured retention",
			len(zero))
	}

	configured := GetPathStatsWindow(context.Background(), 7)

	if len(zero) != len(configured) {
		t.Errorf("GetPathStatsWindow(0) returned %d rows and (7) returned %d; "+
			"an unset window must fall back to the configured retention rather "+
			"than to a cutoff of its own", len(zero), len(configured))
	}

	// A negative window is not a shorter window; it must not select more than
	// the configured one.
	if got := GetPathStatsWindow(context.Background(), -1); len(got) > len(configured) {
		t.Errorf("GetPathStatsWindow(-1) returned %d rows, more than the "+
			"configured window's %d", len(got), len(configured))
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
	t.Cleanup(func() { withStore(t) })

	if got := GetTrace(time.Now().UTC(), "anything"); got != nil {
		t.Errorf("GetTrace with no store = %+v, want nil", got)
	}
}

// TestGetTraceReturnsAStoredTrace is the assertion the other two cannot make.
// Both of them are satisfied by a function that returns a constant nil, so
// without this one the whole happy path is unpinned -- GetTrace could stop
// finding anything at all and the suite would stay green.
func TestGetTraceReturnsAStoredTrace(t *testing.T) {
	withStore(t)

	const id = "trace-round-trip"
	now := time.Now().UTC()
	RecordTrace(id, "GET /api/thing", "svc", "route-1", 12.5, now,
		"200", "/api/thing", "203.0.113.4", "fp", "US", "curl/8", http.MethodGet,
		"", "/api/thing", "ja4", "ja4h", nil, nil, "", 100, 0, 0, 0, 0)

	// Trace writes are buffered and flushed on an interval (2s at the standard
	// tier), so this polls rather than assuming the write already landed --
	// asserting once immediately after RecordTrace fails, which is how the
	// buffering became visible.
	var got *TraceRecord
	deadline := time.Now().Add(15 * time.Second)
	for got == nil && time.Now().Before(deadline) {
		if got = GetTrace(now, id); got == nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if got == nil {
		t.Fatal("GetTrace did not return a trace recorded 15s earlier; the " +
			"traces view would be empty for every request the gateway served")
	}
	if got.ID != id {
		t.Errorf("ID = %q, want %q", got.ID, id)
	}
}
