// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func TestPlanSnapshotReads(t *testing.T) {
	now := time.Now()
	fresh := &MetricsSnapshot{aggregatesAt: now.Add(-10 * time.Second)}
	stale := &MetricsSnapshot{aggregatesAt: now.Add(-2 * time.Minute)}
	never := &MetricsSnapshot{}

	cases := []struct {
		name    string
		prev    *MetricsSnapshot
		watched bool
		want    snapshotReads
	}{
		{"nobody watching reads nothing, even when stale", stale, false, snapshotReads{}},
		{"nobody watching reads nothing at startup", nil, false, snapshotReads{}},
		{"watched with fresh aggregates reads the newest threats only", fresh, true, snapshotReads{recent: true}},
		{"watched with stale aggregates reads everything", stale, true, allReads},
		{"watched with aggregates never read reads everything", never, true, allReads},
		{"watched at startup reads everything", nil, true, allReads},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := planSnapshotReads(tc.prev, now, tc.watched, time.Minute); got != tc.want {
				t.Fatalf("planSnapshotReads = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// aggregateReads is DashboardAggregateReadsTotal's value.
func aggregateReads(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := DashboardAggregateReadsTotal.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// isolateDashboard gives the test its own published snapshot and demand clock,
// with nobody subscribed, and a store holding n threats.
func isolateDashboard(t *testing.T, threats int) {
	t.Helper()
	prevSnap, prevDemand := lastSnapshot.Load(), dashboardDemandAt.Load()
	lastSnapshot.Store(nil)
	dashboardDemandAt.Store(0)
	t.Cleanup(func() {
		lastSnapshot.Store(prevSnap)
		dashboardDemandAt.Store(prevDemand)
	})
	if n := MetricsBroadcaster.Len(); n != 0 {
		t.Fatalf("%d subscribers left over from another test", n)
	}

	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore("sqlite://"+filepath.Join(t.TempDir(), "dashboard.db"), 7); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })

	s := getStore()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := s.threatInsertStmt(tx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range threats {
		th := &SecurityThreat{ID: fmt.Sprintf("t-%03d", i), Type: "sqli", Category: "waf", SourceIP: "203.0.113.9", Time: time.Now().Add(-time.Duration(i) * time.Second)}
		if !s.execThreat(tx, stmt, th, "") {
			t.Fatalf("seed %d failed", i)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// The snapshot loop used to read every dashboard aggregate on every tick --
// four of them scans of all of security_threats -- whether or not anyone had
// the dashboard open. With nobody watching it must not read them at all.
func TestUnwatchedSnapshotLoopReadsNoAggregates(t *testing.T) {
	isolateDashboard(t, 3)
	before := aggregateReads(t)

	for range 5 {
		now := time.Now()
		refreshSnapshot(t.Context(), planSnapshotReads(lastSnapshot.Load(), now, dashboardWatched(now), time.Minute))
	}

	if got := aggregateReads(t) - before; got != 0 {
		t.Fatalf("5 refreshes with nobody watching read the aggregates %v times, want 0", got)
	}
	if snap := GetLastSnapshot(); snap == nil {
		t.Fatal("the unwatched refreshes published nothing; the aggregator and status card read this snapshot")
	}
}

// Once someone watches, the aggregates are read once and then not again
// until they are an interval old, while the newest threats are read every
// tick.
func TestWatchedSnapshotLoopReadsAggregatesOncePerInterval(t *testing.T) {
	isolateDashboard(t, 3)
	ch := MetricsBroadcaster.Subscribe()
	defer MetricsBroadcaster.Unsubscribe(ch)
	before := aggregateReads(t)

	for range 5 {
		now := time.Now()
		refreshSnapshot(t.Context(), planSnapshotReads(lastSnapshot.Load(), now, dashboardWatched(now), time.Minute))
	}

	if got := aggregateReads(t) - before; got != 1 {
		t.Fatalf("5 watched refreshes inside one interval read the aggregates %v times, want 1", got)
	}
	snap := GetLastSnapshot()
	if snap.Security.TotalAnomalies != 3 || len(snap.Security.RecentAnomalies) != 3 {
		t.Fatalf("watched snapshot has total %d and %d recent threats, want 3 and 3",
			snap.Security.TotalAnomalies, len(snap.Security.RecentAnomalies))
	}
}

// A viewer arriving after a quiet period gets current numbers: the stale
// snapshot is read again once, however many viewers arrive together.
func TestFirstViewerAfterAQuietPeriodReadsOnceForEveryone(t *testing.T) {
	isolateDashboard(t, 4)
	refreshSnapshot(t.Context(), snapshotReads{}) // what the unwatched loop publishes
	before := aggregateReads(t)

	var wg sync.WaitGroup
	totals := make([]int64, 8)
	for i := range totals {
		wg.Go(func() {
			snap, err := CollectMetricsSnapshot(t.Context(), 50, 0)
			if err != nil {
				t.Errorf("CollectMetricsSnapshot: %v", err)
				return
			}
			totals[i] = snap.Security.TotalAnomalies
		})
	}
	wg.Wait()

	if got := aggregateReads(t) - before; got != 1 {
		t.Fatalf("8 viewers arriving together read the aggregates %v times, want 1", got)
	}
	for i, total := range totals {
		if total != 4 {
			t.Errorf("viewer %d saw %d threats, want 4", i, total)
		}
	}
	if !dashboardWatched(time.Now()) {
		t.Error("a request for the snapshot did not count as someone watching")
	}
}

// The Security Hub pages through recent threats with its own limit. Each page
// used to collect a whole new snapshot, every aggregate read included; now it
// reads that page and nothing else.
func TestAnotherPageOfThreatsReadsOnlyThatPage(t *testing.T) {
	isolateDashboard(t, 25)
	if _, err := CollectMetricsSnapshot(t.Context(), 50, 0); err != nil {
		t.Fatal(err)
	}
	published := GetLastSnapshot()
	before := aggregateReads(t)

	page, err := CollectMetricsSnapshot(t.Context(), 10, 20)
	if err != nil {
		t.Fatal(err)
	}

	if got := aggregateReads(t) - before; got != 0 {
		t.Fatalf("a page of threats read the aggregates %v times, want 0", got)
	}
	if n := len(page.Security.RecentAnomalies); n != 5 {
		t.Fatalf("page at offset 20 of 25 threats holds %d, want 5", n)
	}
	if page.Security.TotalAnomalies != 25 {
		t.Fatalf("page reports %d threats in total, want 25", page.Security.TotalAnomalies)
	}
	if len(published.Security.RecentAnomalies) != 25 || GetLastSnapshot() != published {
		t.Fatal("reading a page changed the published snapshot")
	}
}

// A viewer wakes the loop only when the aggregates went stale while nobody
// watched. Waking it on every request would turn a client polling the
// snapshot into one refresh per request.
func TestViewerWakesTheLoopOnlyAfterAQuietPeriod(t *testing.T) {
	prev := lastSnapshot.Load()
	t.Cleanup(func() { lastSnapshot.Store(prev) })
	drain := func() bool {
		select {
		case <-snapshotWake:
			return true
		default:
			return false
		}
	}
	drain()

	lastSnapshot.Store(&MetricsSnapshot{aggregatesAt: time.Now()})
	NoteDashboardViewer()
	if drain() {
		t.Fatal("a viewer woke the loop while the aggregates were current")
	}

	lastSnapshot.Store(&MetricsSnapshot{aggregatesAt: time.Now().Add(-time.Hour)})
	NoteDashboardViewer()
	if !drain() {
		t.Fatal("a viewer after a quiet period did not wake the loop")
	}
}
