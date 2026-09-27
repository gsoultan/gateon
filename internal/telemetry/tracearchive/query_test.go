// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tracearchive

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// timeline puts two archived hours before the live store's oldest trace and
// five traces in the store. c2 and c3 start in the same nanosecond, so their
// order -- and a page break between them -- comes down to the ID in the key.
func timeline(t *testing.T) (base time.Time, oldestFirst []string) {
	t.Helper()
	openStore(t)
	root := enableArchive(t)
	base = time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Hour)
	older, old := SegmentAt(base.Add(-3*time.Hour)), SegmentAt(base.Add(-2*time.Hour))
	same := old.Start().Add(7 * time.Minute)
	writeFile(t, root, older,
		testTrace{id: "c0", at: older.Start().Add(time.Minute)},
		testTrace{id: "c1", at: older.Start().Add(2 * time.Minute), status: "503"},
	)
	writeFile(t, root, old,
		testTrace{id: "c2", at: same},
		testTrace{id: "c3", at: same},
		testTrace{id: "c4", at: old.Start().Add(9 * time.Minute), method: "POST"},
		testTrace{id: "c5", at: old.Start().Add(59 * time.Minute)},
	)
	var hot []testTrace
	for i, id := range seq("h", 5) {
		hot = append(hot, testTrace{id: id, at: base.Add(time.Duration(i+1) * time.Minute)})
	}
	hot[3].status = "500"
	store(t, hot...)
	return base, []string{"c0", "c1", "c2", "c3", "c4", "c5", "h00", "h01", "h02", "h03", "h04"}
}

// pages runs a query to the end and returns every trace ID in the order the
// pages gave them.
func pages(t *testing.T, q Query) []string {
	t.Helper()
	var got []string
	for range 1000 {
		res, err := Search(context.Background(), q)
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if len(res.Traces) > q.Limit {
			t.Fatalf("a page of %d traces, over the limit %d", len(res.Traces), q.Limit)
		}
		for _, tr := range res.Traces {
			got = append(got, tr.ID)
		}
		if res.NextCursor == "" {
			return got
		}
		q.Cursor = res.NextCursor
	}
	t.Fatal("the query never reached the end of its period")
	return nil
}

// The store and the archive read as one timeline, in either direction, and
// paging through it neither repeats nor skips a trace -- including at a page
// break between two traces that started in the same nanosecond.
func TestSearch_PagesOneTimelineAcrossStoreAndArchive(t *testing.T) {
	base, oldestFirst := timeline(t)
	period := Query{From: base.Add(-3 * time.Hour), To: base.Add(time.Hour)}
	newestFirst := slices.Clone(oldestFirst)
	slices.Reverse(newestFirst)

	for _, limit := range []int{1, 2, 3, 4, 100} {
		q := period
		q.Limit = limit
		if got := pages(t, q); !slices.Equal(got, newestFirst) {
			t.Fatalf("newest first, %d a page: %v\nwant %v", limit, got, newestFirst)
		}
		q.OldestFirst = true
		if got := pages(t, q); !slices.Equal(got, oldestFirst) {
			t.Fatalf("oldest first, %d a page: %v\nwant %v", limit, got, oldestFirst)
		}
	}
}

func TestSearch_NarrowsToThePeriod(t *testing.T) {
	base, _ := timeline(t)
	// The archived hour before base, and the store's first two minutes.
	q := Query{From: base.Add(-2 * time.Hour), To: base.Add(2*time.Minute + time.Second), Limit: 100, OldestFirst: true}
	if got, want := pages(t, q), []string{"c2", "c3", "c4", "c5", "h00", "h01"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestSearch_Filters(t *testing.T) {
	base, _ := timeline(t)
	period := Query{From: base.Add(-3 * time.Hour), To: base.Add(time.Hour), Limit: 100, OldestFirst: true}
	for name, tc := range map[string]struct {
		filter Filter
		want   []string
	}{
		"errors":          {Filter{Status: "errors"}, []string{"c1", "h03"}},
		"5xx":             {Filter{Status: "5xx"}, []string{"c1", "h03"}},
		"2xx":             {Filter{Status: "2xx"}, []string{"c0", "c2", "c3", "c4", "c5", "h00", "h01", "h02", "h04"}},
		"method any case": {Filter{Method: "post"}, []string{"c4"}},
		"text in the ID":  {Filter{Text: "H0"}, []string{"h00", "h01", "h02", "h03", "h04"}},
		"text in a path":  {Filter{Text: "ARCHIVED"}, []string{"c0", "c1", "c2", "c3", "c4", "c5"}},
	} {
		t.Run(name, func(t *testing.T) {
			q := period
			q.Filter = tc.filter
			if got := pages(t, q); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// A filter that matches almost nothing stops at the scan budget with what it
// has, says so, and carries on from there when asked.
func TestSearch_StopsAtTheBudgetAndResumes(t *testing.T) {
	base, _ := timeline(t)
	q := Query{From: base.Add(-3 * time.Hour), To: base.Add(time.Hour), Limit: 10, Filter: Filter{Text: "c0"}, budget: 3}

	first, err := Search(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Partial || first.NextCursor == "" || len(first.Traces) != 0 {
		t.Fatalf("first page = %+v; want no matches yet, marked partial, with a cursor", first)
	}
	if got := pages(t, q); !slices.Equal(got, []string{"c0"}) {
		t.Fatalf("resumed to the end, got %v, want [c0]", got)
	}
}

// One unreadable hour does not blank the rest of the period.
func TestSearch_PassesOverADamagedHour(t *testing.T) {
	base, _ := timeline(t)
	damaged := SegmentAt(base.Add(-3 * time.Hour))
	if err := os.WriteFile(damaged.path(CurrentSettings().Dir), []byte("not a segment"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := Query{From: base.Add(-3 * time.Hour), To: base.Add(time.Hour), Limit: 100, OldestFirst: true}
	if got := pages(t, q); !slices.Equal(got, []string{"c2", "c3", "c4", "c5", "h00", "h01", "h02", "h03", "h04"}) {
		t.Fatalf("got %v", got)
	}
}

func TestSearch_RefusesWhatItCannotAnswer(t *testing.T) {
	now := time.Now().UTC()
	for name, q := range map[string]Query{
		"no period":       {},
		"backwards":       {From: now, To: now.Add(-time.Hour)},
		"empty":           {From: now, To: now},
		"over 400 days":   {From: now.AddDate(-2, 0, 0), To: now},
		"before 1970":     {From: time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), To: now},
		"unknown status":  {From: now.Add(-time.Hour), To: now, Filter: Filter{Status: "6xx"}},
		"forged cursor":   {From: now.Add(-time.Hour), To: now, Cursor: "not-a-cursor"},
		"cursor too long": {From: now.Add(-time.Hour), To: now, Cursor: longCursor(now)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Search(context.Background(), q); !errors.Is(err, ErrInvalidQuery) {
				t.Fatalf("Search = %v, want ErrInvalidQuery", err)
			}
		})
	}
}

// longCursor is a well-formed key, a timestamp and an ID, longer than any a
// query issues, so only the length check can refuse it.
func longCursor(at time.Time) string {
	key := telemetry.AppendTraceKey(nil, at, strings.Repeat("x", 2*maxCursorLen))
	return base64.RawURLEncoding.EncodeToString(key)
}

// A gateway whose trace store failed to open still answers from the archive; a
// period reaching into the future is not an error because nothing is recent.
func TestSearch_WithNoTraceStoreReadsTheArchive(t *testing.T) {
	root := enableArchive(t)
	_ = telemetry.ClosePathStatsStore(context.Background())
	seg := SegmentAt(time.Now().UTC().Add(-2 * time.Hour))
	writeFile(t, root, seg, testTrace{id: "kept", at: seg.Start().Add(time.Minute)})

	q := Query{From: seg.Start(), To: time.Now().Add(time.Hour), Limit: 10}
	if got := pages(t, q); !slices.Equal(got, []string{"kept"}) {
		t.Fatalf("got %v, want the archived trace", got)
	}
}

// A trace's ID is the client's X-Request-ID. A page ending on a long one used
// to hand out a cursor the next call refused as not issued by this server.
func TestSearch_PagesPastALongRequestID(t *testing.T) {
	openStore(t)
	enableArchive(t)
	now := time.Now().UTC()
	store(t,
		testTrace{id: "older", at: now.Add(-2 * time.Minute)},
		testTrace{id: strings.Repeat("x", 1100), at: now.Add(-time.Minute)},
	)
	if got := pages(t, Query{From: now.Add(-time.Hour), To: now, Limit: 1}); len(got) != 2 || got[1] != "older" {
		t.Fatalf("paged %d traces (%q...), want both", len(got), got)
	}
}

// The ID a search lists is the ID that opens the trace, including one the
// client sent as bytes that are not UTF-8.
func TestSearch_ATraceListedWithAnOddIDOpensByIt(t *testing.T) {
	openStore(t)
	enableArchive(t)
	h := SegmentAt(time.Now().UTC().Add(-5 * time.Hour))
	at := h.Start().Add(10 * time.Minute)
	store(t, testTrace{id: "\xff\xfe", at: at})
	if _, err := (&Archiver{}).reconcile(context.Background(), CurrentSettings(), h); err != nil {
		t.Fatal(err)
	}
	res, err := Search(context.Background(), Query{From: h.Start(), To: h.End(), Limit: 10})
	if err != nil || len(res.Traces) != 1 {
		t.Fatalf("Search = %d traces, %v", len(res.Traces), err)
	}
	if rec, err := Lookup(context.Background(), at, res.Traces[0].ID); rec == nil || err != nil {
		t.Fatalf("Lookup(%q) = %v, %v; the listed ID does not open the archived trace", res.Traces[0].ID, rec, err)
	}
}

// One search runs at a time. One that is waiting gives up when its caller
// does, rather than holding a request open behind a long search.
func TestSearch_StopsWaitingWhenItsCallerDoes(t *testing.T) {
	querySlots <- struct{}{}
	t.Cleanup(func() { <-querySlots })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	now := time.Now().UTC()
	start := time.Now()
	_, err := Search(ctx, Query{From: now.Add(-time.Hour), To: now})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("Search behind a busy slot = %v after %v; want the caller's deadline", err, time.Since(start))
	}
}

// Case is folded for ASCII only, in one pass over each field, however long
// the path and the text are.
func TestFilter_MatchesIgnoringASCIICase(t *testing.T) {
	f := Filter{Text: "OrDeRs"}.compile()
	for path, want := range map[string]bool{
		"/API/ORDERS/7":                       true,
		"/api/orders":                         true,
		"/api/order":                          false,
		"/Éorders":                            true,
		"/api/örders":                         false,
		strings.Repeat("a", 1<<20) + "orders": true,
	} {
		if got := f.matches(&telemetry.TraceRecord{Path: path}); got != want {
			t.Errorf("Text %q against %q...: %v, want %v", "OrDeRs", path[:min(len(path), 16)], got, want)
		}
	}
	accented := Filter{Text: "É"}.compile()
	if accented.matches(&telemetry.TraceRecord{Path: "/é"}) {
		t.Error("a non-ASCII letter was folded; the filter documents ASCII case only")
	}
}
