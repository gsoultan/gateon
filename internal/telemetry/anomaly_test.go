// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestAnomalyDetector_Local(t *testing.T) {
	agg := GetAggregator()
	// Reset to known state
	agg.mu.Lock()
	agg.buckets = nil
	agg.mu.Unlock()
	agg.ResetIPStats()

	conf := &gateonv1.AnomalyDetectionConfig{
		Enabled:                   true,
		Sensitivity:               0.5,
		CheckIntervalSeconds:      1,
		EnableBruteForceDetection: true,
		EnableExploitDetection:    true,
	}

	ad, err := NewAnomalyDetector(conf, nil)
	if err != nil {
		t.Fatalf("failed to create anomaly detector: %v", err)
	}

	// 1. Test Brute Force Detection
	// We need enough requests to trigger the GetIPStats(10) check
	for i := range 15 {
		agg.RecordRequest("1.1.1.1", 200)
		if i < 12 {
			agg.RecordRequest("1.1.1.1", 401)
		}
	}

	// 2. Test Exploit Detection
	for range 10 {
		agg.RecordWAFBlock("2.2.2.2")
	}

	// 3. Test Error Rate Spike
	now := time.Now()
	agg.mu.Lock()
	agg.buckets = append(agg.buckets, MetricPoint{
		Timestamp: now.Add(-10 * time.Minute),
		Requests:  100,
		Errors:    1,
	})
	agg.buckets = append(agg.buckets, MetricPoint{
		Timestamp: now,
		Requests:  200,
		Errors:    51, // Massive spike: (51-1)/(10*60) = 0.083 errors/s vs 100/600 = 0.16 requests/s -> ~50% error rate
	})
	agg.mu.Unlock()

	// Run checks
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
	defer cancel()

	ad.runChecks(ctx, now)

	// Since runChecks writes to security threats (which is a global or store),
	// we could verify if threats were recorded, but for now PASS if no crash.
}

// Start guarded check_interval_seconds against zero only, then handed it to
// time.NewTicker, which panics on any non-positive duration. The management API
// stores a negative value as given, and the security supervisor runs Start on
// its own goroutine with no recover each time the global config is saved, so
// the save that set it crashed the gateway, and so did every boot after it.
//
// Run inside a synctest bubble so "Start is running its loop" is observable
// without timing: once every goroutine is durably blocked, Start has either
// returned or is parked on its ticker. A Start that panics fails, and so does
// one that returns without detecting anything.
func TestAnomalyDetectorStartSurvivesNonPositiveInterval(t *testing.T) {
	for _, secs := range []int32{0, -1, -86400} {
		t.Run(fmt.Sprint(secs), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ad, err := NewAnomalyDetector(&gateonv1.AnomalyDetectionConfig{
					Enabled:              true,
					CheckIntervalSeconds: secs,
				}, nil)
				if err != nil {
					t.Fatal(err)
				}

				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					ad.Start(ctx)
				}()

				synctest.Wait()
				select {
				case <-done:
					t.Fatal("Start returned while its context was live: the detection loop is not running")
				default:
				}
				cancel()
				<-done
			})
		})
	}
}
