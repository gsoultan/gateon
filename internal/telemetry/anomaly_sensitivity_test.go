// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestBruteForceDetectionDoesNotFallAsSensitivityRises pins the direction of the
// Sensitivity setting for brute-force detection.
//
// The dashboard offers Sensitivity from 0 to 1 (SettingsPage.tsx), the shipped
// default is 0.5, and the exploit, error-rate and latency checks all lower
// their bar as it rises. Brute force compared the failure rate against
// Sensitivity*1.5, so it raised its bar instead: at 0.7 and above the bar
// passed 1.0, a rate no client can reach, and brute-force detection stopped
// firing for good -- at exactly the settings an operator picks to catch more.
func TestBruteForceDetectionDoesNotFallAsSensitivityRises(t *testing.T) {
	initAnomalyTestStore(t)

	// Every request failing authentication: nothing is a clearer brute force.
	for i, sensitivity := range []float64{0.5, 0.7, 0.9, 1.0} {
		ip := fmt.Sprintf("198.51.100.%d", 130+i)
		if !reportsBruteForce(t, sensitivity, ip, 20, 20) {
			t.Errorf("sensitivity %.1f: all 20 requests from %s failed authentication and no brute force was reported",
				sensitivity, ip)
		}
	}

	// A client failing 12 of 20 logins. Wherever the bar sits, raising the
	// sensitivity must not make a detected client undetected.
	detectedBelow := -1.0
	detectedAt := map[float64]bool{}
	for i, sensitivity := range []float64{0, 0.25, 0.5, 0.75, 1.0} {
		ip := fmt.Sprintf("198.51.100.%d", 140+i)
		detected := reportsBruteForce(t, sensitivity, ip, 20, 12)
		detectedAt[sensitivity] = detected
		if detected && detectedBelow < 0 {
			detectedBelow = sensitivity
		}
		if !detected && detectedBelow >= 0 {
			t.Errorf("12 of 20 failures were reported at sensitivity %.2f and not at the higher %.2f",
				detectedBelow, sensitivity)
		}
	}
	// The default's bar is a failure rate above 0.75, as it always was; 0.6 is
	// under it. Moving it would silently re-price every install on the default.
	if detectedAt[0.5] {
		t.Error("the default sensitivity reported a 0.6 failure rate; its bar is 0.75")
	}
	// Zero switches the check off, as it does the exploit and Z-score checks.
	if detectedAt[0] {
		t.Error("sensitivity 0 reported a brute force; it switches every other check off")
	}
	if !detectedAt[1.0] {
		t.Error("the highest sensitivity did not report 12 of 20 failed logins")
	}
}

// reportsBruteForce runs one detection pass over requests from ip, failures of
// them answered 401, and reports whether a brute-force threat was recorded.
func reportsBruteForce(t *testing.T, sensitivity float64, ip string, requests, failures int) bool {
	t.Helper()
	agg := newIsolatedAggregator()
	for i := range requests {
		status := http.StatusOK
		if i < failures {
			status = http.StatusUnauthorized
		}
		agg.RecordRequest(ip, status)
	}
	ad := &AnomalyDetector{
		config: &gateonv1.AnomalyDetectionConfig{
			Enabled: true, Sensitivity: sensitivity, EnableBruteForceDetection: true,
		},
		aggregator: agg,
	}
	t.Cleanup(func() { _ = MarkIPUnmitigated(ip) })
	ad.runChecks(t.Context(), time.Now())
	return threatRecorded(t, "brute_force_attempt", ip)
}

// newIsolatedAggregator is an aggregator no other test or loop writes to.
func newIsolatedAggregator() *LocalMetricsAggregator {
	return &LocalMetricsAggregator{
		buckets:       make([]MetricPoint, 0, 60),
		ipStats:       &sync.Map{},
		maxBuckets:    60,
		StatsRequests: &RunningStats{},
		StatsLatency:  &RunningStats{},
	}
}

// initAnomalyTestStore gives the test its own telemetry store, so recorded
// threats can be read back after FlushThreats.
func initAnomalyTestStore(t *testing.T) {
	t.Helper()
	_ = ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(filepath.Join(t.TempDir(), "anomaly.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = ClosePathStatsStore(context.Background()) })
}

// threatRecorded reports whether a threat of the given type from ip reached the
// store. FlushThreats first, so a negative answer means it was never recorded
// rather than that it had not been written yet.
func threatRecorded(t *testing.T, threatType, ip string) bool {
	t.Helper()
	FlushThreats()
	for _, th := range GetSecurityThreatsLite(t.Context(), 1000, 0, nil) {
		if th.Type == threatType && th.SourceIP == ip {
			return true
		}
	}
	return false
}
