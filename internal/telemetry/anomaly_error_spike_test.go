// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestErrorRateSpikeIsJudgedAgainstTheLastHour drives the error-rate check the
// way the gateway does -- an hour of minute snapshots through takeSnapshot,
// then the detector's check -- and asks whether five minutes of 40% 5xx
// responses are reported.
//
// The check scored the current error rate, in errors per second, against
// running statistics fed with the cumulative 5xx counter: after an hour at a
// few errors a minute the "baseline" had a mean in the hundreds, so a rate of
// 8/s sat several deviations *below* it and no spike could ever be reported. A
// healthy service whose baseline is no errors at all has no spread either, and
// the Z-score's guard against dividing by zero answered 0 for it -- blind to the
// first outage it would ever see.
func TestErrorRateSpikeIsJudgedAgainstTheLastHour(t *testing.T) {
	initAnomalyTestStore(t)
	prev := lastSnapshot.Load()
	t.Cleanup(func() { lastSnapshot.Store(prev) })

	cases := []struct {
		name     string
		baseline func(minute int) float64 // 5xx responses in that minute of the hour
		outage   float64                  // 5xx a minute in the last five
		want     bool
	}{
		{name: "no errors all hour, then an outage", baseline: func(int) float64 { return 0 }, outage: 480, want: true},
		{name: "a few errors a minute, then an outage", baseline: func(m int) float64 { return float64(3 + m%5) }, outage: 480, want: true},
		{name: "a steady high error rate, unchanged", baseline: func(m int) float64 { return float64(380 + 10*(m%5)) }, outage: 400, want: false},
	}
	for i, tc := range cases {
		// A real timestamp for the finding, so the store keeps it; the bubble's
		// clock only drives the aggregator's windows.
		now := time.Now().Add(time.Duration(i) * time.Second)
		synctest.Test(t, func(t *testing.T) {
			agg := newIsolatedAggregator()
			hourThenOutage(t, agg, tc.baseline, tc.outage)
			ad := &AnomalyDetector{
				config:     &gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: 0.5},
				aggregator: agg,
			}
			ad.runChecks(t.Context(), now)
		})
		if got := threatWithIDRecorded(t, fmt.Sprintf("anomaly-error-rate-%d", now.Unix())); got != tc.want {
			t.Errorf("%s: error_rate_spike reported = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// hourThenOutage feeds the aggregator one snapshot a minute: an hour at 20
// requests a second with baseline(m) errors in minute m, then five minutes with
// outage errors each. The counters are cumulative, as Prometheus reports them.
func hourThenOutage(t *testing.T, agg *LocalMetricsAggregator, baseline func(int) float64, outage float64) {
	t.Helper()
	var requests, errors float64
	snapshot := func() {
		lastSnapshot.Store(&MetricsSnapshot{GoldenSignals: GoldenSignals{
			RequestsTotal: requests, ErrorsTotal: errors, P99LatencyMs: 40,
		}})
		agg.takeSnapshot(t.Context())
	}
	snapshot()
	for m := range 60 {
		time.Sleep(time.Minute)
		requests += 1200
		errors += baseline(m)
		snapshot()
	}
	for range 5 {
		time.Sleep(time.Minute)
		requests += 1200
		errors += outage
		snapshot()
	}
}

// threatWithIDRecorded reports whether a threat with this ID reached the store.
func threatWithIDRecorded(t *testing.T, id string) bool {
	t.Helper()
	FlushThreats()
	for _, th := range GetSecurityThreatsLite(t.Context(), 1000, 0, nil) {
		if th.ID == id {
			return true
		}
	}
	return false
}
