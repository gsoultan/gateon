// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// storeTraces records traces that started at the given times and waits until
// the store has written them.
func storeTraces(t *testing.T, at map[string]time.Time) {
	t.Helper()
	for id, ts := range at {
		RecordTrace(id, "GET /", "svc", "r", 1, ts, "200", "/", "192.0.2.1", "", "", "", "GET", "", "/", "", "",
			nil, nil, "none", 0, 0, 0, 0, 0)
	}
	FlushThreats() // the store's barrier for every intake, traces included
}

func scanIDs(t *testing.T, sc TraceScan) []string {
	t.Helper()
	var ids []string
	err := ScanTraces(context.Background(), sc, func(key, _ []byte) bool {
		ids = append(ids, string(key[9:]))
		return true
	})
	if err != nil {
		t.Fatalf("ScanTraces: %v", err)
	}
	return ids
}

func TestScanTraces_RangeDirectionAndCursor(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	freshStore(t)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute)
	same := base.Add(2 * time.Minute)
	storeTraces(t, map[string]time.Time{
		"a": base, "b": base.Add(time.Minute), "c1": same, "c2": same, "d": base.Add(3 * time.Minute),
	})

	if got := scanIDs(t, TraceScan{From: base.Add(time.Minute), To: base.Add(3 * time.Minute)}); !slices.Equal(got, []string{"b", "c1", "c2"}) {
		t.Fatalf("[+1m, +3m) = %v", got)
	}
	if got := scanIDs(t, TraceScan{Desc: true}); !slices.Equal(got, []string{"d", "c2", "c1", "b", "a"}) {
		t.Fatalf("all, newest first = %v", got)
	}
	// A cursor between two traces of the same nanosecond resumes strictly past
	// it, either way.
	at := AppendTraceKey(nil, same, "c1")
	if got := scanIDs(t, TraceScan{After: at}); !slices.Equal(got, []string{"c2", "d"}) {
		t.Fatalf("after c1 = %v", got)
	}
	if got := scanIDs(t, TraceScan{After: at, Desc: true}); !slices.Equal(got, []string{"b", "a"}) {
		t.Fatalf("before c1 = %v", got)
	}
	if got := scanIDs(t, TraceScan{From: base.Add(3 * time.Minute), To: base}); len(got) != 0 {
		t.Fatalf("an inverted range = %v, want nothing", got)
	}
}

// The prune guard exists to hold traces back for the archive. It must never
// make the store delete more than retention says, and the one answer that
// cannot be a time -- the zero time -- must delete nothing: its UnixNano wraps
// to a key above every trace, and deleting up to it empties the store.
func TestPruneTraces_GuardCanOnlyHoldBack(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	now := time.Now().UTC()
	for name, tc := range map[string]struct {
		guard func(cutoff time.Time) time.Time
		kept  []string
	}{
		"no guard":          {nil, []string{"recent"}},
		"holding back":      {func(c time.Time) time.Time { return c.Add(-36 * time.Hour) }, []string{"old", "recent"}},
		"asking for more":   {func(time.Time) time.Time { return now }, []string{"recent"}},
		"answering nothing": {func(time.Time) time.Time { return time.Time{} }, []string{"oldest", "older", "old", "recent"}},
	} {
		t.Run(name, func(t *testing.T) {
			freshStore(t)
			t.Cleanup(func() { SetTracePruneGuard(nil) })
			storeTraces(t, map[string]time.Time{"recent": now.AddDate(0, 0, -1)})
			cutoff := TracePruneCutoff(now)
			storeTraces(t, map[string]time.Time{
				"oldest": cutoff.Add(-72 * time.Hour),
				"older":  cutoff.Add(-48 * time.Hour),
				"old":    cutoff.Add(-24 * time.Hour),
			})
			SetTracePruneGuard(tc.guard)

			getStore().pruneTraces()

			got := scanIDs(t, TraceScan{})
			if !slices.Equal(got, tc.kept) {
				t.Fatalf("kept %v, want %v", got, tc.kept)
			}
		})
	}
}

// Traces older than the floor must be looked for elsewhere; traces newer than
// it are all here. A trace written below the last prune -- a request that
// outlived retention -- does not lower the floor.
func TestTraceHotFloor(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	freshStore(t)
	t.Cleanup(func() { SetTracePruneGuard(nil) })

	if floor := TraceHotFloor(context.Background()); time.Since(floor) > time.Minute {
		t.Fatalf("an empty store's floor is %v; with nothing stored, everything is older", floor)
	}

	now := time.Now().UTC()
	oldest := now.Add(-time.Hour)
	storeTraces(t, map[string]time.Time{"x": oldest, "y": now.Add(-time.Minute)})
	if floor := TraceHotFloor(context.Background()); !floor.Equal(oldest.Truncate(0)) {
		t.Fatalf("floor = %v, want the oldest trace %v", floor, oldest)
	}

	cutoff := TracePruneCutoff(now)
	getStore().pruneTraces()
	storeTraces(t, map[string]time.Time{"outlived-retention": cutoff.Add(-time.Hour)})
	if floor := TraceHotFloor(context.Background()); floor.Before(cutoff.Add(-time.Second)) {
		t.Fatalf("floor = %v; a late trace pulled it below the prune at %v", floor, cutoff)
	}
}

// A search decides where the store's part of a period starts, then reads it.
// A view taken first holds the store still in between: a prune that lands
// after the decision must not take the hour the decision sent the reader to.
func TestTraceView_HoldsThroughAPrune(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	freshStore(t)
	// The store's loop sets retention from the profile when it starts, and a
	// flush is answered only once it has: read the cutoff after one.
	FlushThreats()
	now := time.Now().UTC()
	cutoff := TracePruneCutoff(now)
	storeTraces(t, map[string]time.Time{"old": cutoff.Add(-time.Hour), "recent": now.Add(-time.Minute)})

	view, err := OpenTraceView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	floor := view.Floor()
	getStore().pruneTraces()

	var seen []string
	if err := view.Scan(context.Background(), TraceScan{}, func(key, _ []byte) bool {
		seen = append(seen, string(key[9:]))
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(seen, []string{"old", "recent"}) || !view.Floor().Equal(floor) {
		t.Fatalf("view after the prune saw %v with floor %v; want both traces and floor %v", seen, view.Floor(), floor)
	}
	if got := scanIDs(t, TraceScan{}); !slices.Equal(got, []string{"recent"}) {
		t.Fatalf("the prune itself did not happen: store holds %v", got)
	}
}

// Where pruning stopped outlives the process. Forgotten, a trace written below
// it by a request that outlived retention would drag the floor down after a
// restart and hide the archived hours between it and the real prune point.
func TestTraceHotFloor_SurvivesARestart(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "standard")
	dir := t.TempDir()
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(dir, "pebble"))
	open := func() {
		ClosePathStatsStore(context.Background())
		if err := InitPathStatsStore(filepath.Join(dir, "telemetry.db"), 7); err != nil {
			t.Fatalf("InitPathStatsStore: %v", err)
		}
	}
	t.Cleanup(func() { ClosePathStatsStore(context.Background()) })

	open()
	now := time.Now().UTC()
	cutoff := TracePruneCutoff(now)
	storeTraces(t, map[string]time.Time{"old": cutoff.Add(-time.Hour), "recent": now.Add(-time.Minute)})
	getStore().pruneTraces()

	open() // the restart
	storeTraces(t, map[string]time.Time{"outlived-retention": cutoff.Add(-2 * time.Hour)})
	if floor := TraceHotFloor(context.Background()); floor.Before(cutoff.Add(-time.Second)) {
		t.Fatalf("after a restart the floor is %v, below the last prune at %v", floor, cutoff)
	}
}

// The ID is the client's X-Request-ID. Stored as sent, a long one broke every
// cursor that ended on it, and bytes that are not UTF-8 made the archive's
// copy of a trace never match the store's.
func TestStorableTraceID(t *testing.T) {
	for in, want := range map[string]string{
		"req-123":                      "req-123",
		strings.Repeat("x", 1100):      strings.Repeat("x", maxTraceIDBytes),
		"ok\xff\xfeok":                 "ok�ok",
		strings.Repeat("é", 100):       strings.Repeat("é", 64), // 128 bytes, cut on a rune boundary
		strings.Repeat("a", 127) + "é": strings.Repeat("a", 127) + "�",
	} {
		got := storableTraceID(in)
		if got != want || !utf8.ValidString(got) || len(got) > maxTraceIDBytes+2 {
			t.Errorf("storableTraceID(%q...) = %q, want %q", in[:min(len(in), 12)], got, want)
		}
	}

	t.Setenv("GATEON_PROFILE", "standard")
	freshStore(t)
	storeTraces(t, map[string]time.Time{strings.Repeat("y", 2048): time.Now().Add(-time.Minute)})
	if got := scanIDs(t, TraceScan{}); len(got) != 1 || len(got[0]) != maxTraceIDBytes {
		t.Fatalf("stored ID of %d bytes, want %d", len(got[0]), maxTraceIDBytes)
	}
}
