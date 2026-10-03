// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/testutil"
)

// openTrendStore opens the store on databaseURL with no threat in it, and
// closes it with the test. A shared Postgres keeps rows across runs.
func openTrendStore(t *testing.T, databaseURL string) {
	t.Helper()
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(databaseURL, 1); err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
	if _, err := getStore().db.Exec(`DELETE FROM security_threats`); err != nil {
		t.Fatalf("empty security_threats: %v", err)
	}
}

// recordDetectionAt records a threat at a given time through the store's own
// loop and write path. A detection, not a block, so nothing escalates.
func recordDetectionAt(at time.Time) {
	RecordSecurityThreat(SecurityThreat{
		Type: "sqli_detected", Category: "waf", Severity: "low", SourceIP: "198.51.100.77",
		Score: 1, Time: at, ActionTaken: ActionDetected,
	})
}

// TestTheAttackTrendHasABucketPerHourAndDay is T28: the chart was always empty
// on SQLite, the default database. The driver stores a threat's time as Go's
// text form, which SQLite's strftime() and date() cannot parse, so every row
// grouped into one NULL bucket and the reader dropped it. Run on SQLite and,
// when GATEON_TEST_POSTGRES_DSN is set, on Postgres, which stores the same
// local wall clock in a timestamp without a zone.
func TestTheAttackTrendHasABucketPerHourAndDay(t *testing.T) {
	engines := map[string]func(t *testing.T) string{
		"sqlite":   func(t *testing.T) string { return "sqlite://" + filepath.Join(t.TempDir(), "trend.db") },
		"postgres": func(t *testing.T) string { return testutil.PostgresDSN(t, "skipping the Postgres run") },
	}
	for name, dsn := range engines {
		t.Run(name, func(t *testing.T) {
			openTrendStore(t, dsn(t))
			hour := time.Now().Truncate(time.Hour)
			times := []time.Time{
				hour.Add(-150 * time.Minute), // two hours before the current hour
				hour.Add(-50 * time.Minute),  // the previous hour, twice
				hour.Add(-10 * time.Minute),
			}
			for _, at := range times {
				recordDetectionAt(at)
			}
			FlushThreats()

			for _, daily := range []bool{false, true} {
				days := 1
				if daily {
					days = attackTrendDailyThresholdDays + 1
				}
				want := map[int64]uint64{}
				for _, at := range times {
					want[trendBucketStart(at, daily).UnixMilli()]++
				}
				got := map[int64]uint64{}
				for _, s := range GetAttackTrend(context.Background(), days) {
					got[s.Timestamp] += s.Requests
				}
				if len(got) != len(want) {
					t.Fatalf("daily=%v: buckets %v, want %v", daily, got, want)
				}
				for ts, n := range want {
					if got[ts] != n {
						t.Errorf("daily=%v: bucket %s holds %d, want %d (all: %v)",
							daily, time.UnixMilli(ts).Format(time.RFC3339), got[ts], n, got)
					}
				}
			}
		})
	}
}

// TestParseThreatTimestamp covers the forms a stored threat time comes back in.
func TestParseThreatTimestamp(t *testing.T) {
	wib := time.FixedZone("WIB", 7*3600)
	want := time.Date(2026, 10, 2, 16, 39, 31, 975189000, wib)
	cases := map[string]any{
		"go text with monotonic": "2026-10-02 16:39:31.975189 +0700 WIB m=+25.133701085",
		"go text":                []byte("2026-10-02 16:39:31.975189 +0700 WIB"),
		"sqlite text":            "2026-10-02 16:39:31.975189+07:00",
		"rfc3339":                "2026-10-02T16:39:31.975189+07:00",
	}
	for name, in := range cases {
		got, ok := parseThreatTimestamp(in)
		if !ok || !got.Equal(want) {
			t.Errorf("%s: parse(%v) = %v, %v; want %v", name, in, got, ok, want)
		}
	}
	// A Postgres timestamp without a zone: the writer's wall clock, read as
	// local time whatever location the driver labelled it with.
	got, ok := parseThreatTimestamp(time.Date(2026, 10, 2, 16, 0, 0, 0, time.UTC))
	if !ok || got.Location() != time.Local || got.Hour() != 16 {
		t.Errorf("timestamp without zone = %v, %v; want 16:00 local", got, ok)
	}
	if _, ok := parseThreatTimestamp(nil); ok {
		t.Error("parse(nil) reported a time")
	}
}
