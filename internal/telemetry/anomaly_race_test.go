// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"sync"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAnomalyChecksDoNotRaceTheAggregator runs the two loops anomaly detection
// is made of against one aggregator, as the gateway does: the aggregator's
// minute tick (takeSnapshot, which updates the running error and latency
// statistics under the aggregator's lock) and the detector's check interval
// (runChecks, which scores against those statistics).
//
// The checks read the statistics with no lock at all, from their own
// goroutine, so a score could combine a count, mean and variance from two
// different updates. Only meaningful under -race, which is how CI runs it.
func TestAnomalyChecksDoNotRaceTheAggregator(t *testing.T) {
	prev := lastSnapshot.Load()
	lastSnapshot.Store(&MetricsSnapshot{GoldenSignals: GoldenSignals{
		RequestsTotal: 5000, ErrorsTotal: 400, P99LatencyMs: 900,
	}})
	t.Cleanup(func() { lastSnapshot.Store(prev) })

	agg := &LocalMetricsAggregator{
		buckets:       make([]MetricPoint, 0, 60),
		ipStats:       &sync.Map{},
		maxBuckets:    60,
		StatsRequests: &RunningStats{},
		StatsErrors:   &RunningStats{},
		StatsLatency:  &RunningStats{},
	}
	// An older, smaller point inside both windows, so the error-rate check
	// clears its traffic floors and the latency check has a baseline: both
	// reach the statistics.
	agg.buckets = append(agg.buckets, MetricPoint{
		Timestamp: time.Now().Add(-2 * time.Minute), P99Latency: 0.9,
	})
	ad := &AnomalyDetector{
		config:     &gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: 1},
		aggregator: agg,
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 200 {
			agg.takeSnapshot(t.Context())
		}
	})
	wg.Go(func() {
		for range 200 {
			ad.runChecks(t.Context(), time.Now())
		}
	})
	wg.Wait()
}
