// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"math"
	"testing"
)

// GetServiceGoldenSignals is what the canary controller consults at every step
// to decide whether to keep shifting traffic or roll back, and it had no test.
// A wrong error rate or p99 there either aborts a healthy rollout or drives
// through a sick one, and the rollback it triggers is the destructive half.
//
// Each test seeds its own service name so the shared default registry cannot
// leak counts between them, and so a metric some other test in this package
// registered cannot be mistaken for this one's.

func TestGoldenSignalsCountsOnlyTheServiceAsked(t *testing.T) {
	const mine, theirs = "gs-isolation-mine", "gs-isolation-theirs"

	RequestsTotal.WithLabelValues("r1", mine, "GET", "200").Add(10)
	RequestsTotal.WithLabelValues("r2", theirs, "GET", "200").Add(500)
	RequestsTotal.WithLabelValues("r2", theirs, "GET", "500").Add(500)

	gs := GetServiceGoldenSignals(context.Background(), mine)

	if gs.RequestsTotal != 10 {
		t.Errorf("RequestsTotal = %v, want 10; another service's traffic was counted",
			gs.RequestsTotal)
	}
	// theirs is 50% errors. If the filter leaked, this would not be zero -- and
	// the canary would roll back a healthy service because of its neighbour.
	if gs.ErrorRate != 0 {
		t.Errorf("ErrorRate = %v, want 0; another service's failures were counted",
			gs.ErrorRate)
	}
}

func TestGoldenSignalsErrorRateCountsOnly5xx(t *testing.T) {
	const svc = "gs-errorrate"

	RequestsTotal.WithLabelValues("r", svc, "GET", "200").Add(6)
	RequestsTotal.WithLabelValues("r", svc, "GET", "404").Add(2) // client error, not ours
	RequestsTotal.WithLabelValues("r", svc, "GET", "503").Add(2)

	gs := GetServiceGoldenSignals(context.Background(), svc)

	if gs.RequestsTotal != 10 {
		t.Fatalf("RequestsTotal = %v, want 10", gs.RequestsTotal)
	}
	if gs.ErrorsTotal != 2 {
		t.Errorf("ErrorsTotal = %v, want 2; a 4xx is the caller's fault, not the "+
			"service's, and counting it would abort healthy rollouts", gs.ErrorsTotal)
	}
	if gs.ErrorRate != 20 {
		t.Errorf("ErrorRate = %v, want 20 (percent, not fraction)", gs.ErrorRate)
	}
}

// TestGoldenSignalsErrorRateIsAPercentage pins the unit. The canary compares it
// against MaxErrorRate straight from the API, so a fraction here would read as
// 0.2% where the operator configured 20% and the guard would never fire.
func TestGoldenSignalsErrorRateIsAPercentage(t *testing.T) {
	const svc = "gs-percent"

	RequestsTotal.WithLabelValues("r", svc, "GET", "500").Add(1)

	if gs := GetServiceGoldenSignals(context.Background(), svc); gs.ErrorRate != 100 {
		t.Errorf("ErrorRate = %v for an all-5xx service, want 100", gs.ErrorRate)
	}
}

// TestGoldenSignalsWithNoTrafficIsZeroNotNaN guards the division. ErrorsTotal
// over RequestsTotal with no requests is 0/0, and a NaN reaching the canary
// compares false against every threshold -- so a service with no traffic would
// silently pass every safety check rather than failing one.
func TestGoldenSignalsWithNoTrafficIsZeroNotNaN(t *testing.T) {
	// Seeded deliberately, for a *different* service. Without it this test
	// passes against a service filter replaced by `return true`, because run
	// on its own there is nothing in the registry to mis-attribute -- its
	// entire signal was counts other tests happened to leak in first, which is
	// the opposite of the isolation this file claims. Now a broken filter picks
	// this traffic up and the assertions below fail in any run order.
	const other = "gs-service-with-traffic"
	RequestsTotal.WithLabelValues("route-x", other, "GET", "200").Add(7)
	RequestDurationSeconds.WithLabelValues("route-x", other, "GET").Observe(0.25)

	gs := GetServiceGoldenSignals(context.Background(), "gs-service-that-never-served")

	// NaN first: it is what 0/0 produces, and `!= 0` is true for NaN, so the
	// check below would fire first and report "ErrorRate = NaN, want 0"
	// without ever naming the real problem. An earlier version had these the
	// other way round, which made the NaN branch unreachable.
	if math.IsNaN(gs.ErrorRate) {
		t.Error("ErrorRate is NaN; it compares false against every canary " +
			"threshold, so a rollback gate reading it never fires")
	}
	if gs.RequestsTotal != 0 {
		t.Errorf("RequestsTotal = %v, want 0; traffic for another service was "+
			"attributed to one that never served a request", gs.RequestsTotal)
	}
	if gs.ErrorRate != 0 {
		t.Errorf("ErrorRate = %v, want 0", gs.ErrorRate)
	}
	if gs.P99LatencyMs != 0 {
		t.Errorf("P99LatencyMs = %v, want 0; another service's latency was "+
			"attributed here", gs.P99LatencyMs)
	}
}

func TestGoldenSignalsLatencyIsMilliseconds(t *testing.T) {
	const svc = "gs-latency"

	// Seconds in, milliseconds out.
	for range 10 {
		RequestDurationSeconds.WithLabelValues("r", svc, "GET").Observe(0.25)
	}

	gs := GetServiceGoldenSignals(context.Background(), svc)

	if gs.AvgLatencyMs < 200 || gs.AvgLatencyMs > 300 {
		t.Errorf("AvgLatencyMs = %v, want ~250; a seconds-valued latency would "+
			"read as 0.25 against a MaxP99LatencyMs the operator set in ms",
			gs.AvgLatencyMs)
	}
	if gs.P99LatencyMs <= 0 {
		t.Errorf("P99LatencyMs = %v, want a positive estimate", gs.P99LatencyMs)
	}
	if gs.P50LatencyMs > gs.P99LatencyMs {
		t.Errorf("p50 %v exceeds p99 %v", gs.P50LatencyMs, gs.P99LatencyMs)
	}
}

// TestGoldenSignalsCannotAttributeBytesOrInFlightToAService records a real
// limitation rather than letting it stay a silent zero.
//
// GetServiceGoldenSignals filters every family with
// labelValue(m, "service") == serviceID, but gateon_request_bytes_total is
// labelled (route, direction) and gateon_requests_in_flight is labelled (route)
// -- neither carries a service label at all. labelValue returns "" for a label
// that is not there, so the predicate is `"" == serviceID`, false for every
// real service, and these three fields are structurally always zero.
//
// Nothing consumes them today: the canary, the only caller, reads ErrorRate and
// P99LatencyMs. That is why this is pinned rather than fixed -- attributing
// them would mean either resolving service to routes here, which reaches past
// this layer, or adding a service label to two hot-path metrics, which is
// cardinality nobody has asked for. If either happens, this test fails and
// tells whoever did it that the zeroes were known.
func TestGoldenSignalsCannotAttributeBytesOrInFlightToAService(t *testing.T) {
	const svc = "gs-unattributable"

	RequestsTotal.WithLabelValues("r-bytes", svc, "GET", "200").Add(1)
	RequestBytesTotal.WithLabelValues("r-bytes", "in").Add(4096)
	RequestBytesTotal.WithLabelValues("r-bytes", "out").Add(8192)
	RequestsInFlight.WithLabelValues("r-bytes").Set(3)

	gs := GetServiceGoldenSignals(context.Background(), svc)

	if gs.RequestsTotal != 1 {
		t.Fatalf("RequestsTotal = %v, want 1; the service filter itself is broken",
			gs.RequestsTotal)
	}
	for _, tc := range []struct {
		name string
		got  float64
	}{
		{"BytesInTotal", gs.BytesInTotal},
		{"BytesOutTotal", gs.BytesOutTotal},
		{"InFlightTotal", gs.InFlightTotal},
	} {
		if tc.got != 0 {
			t.Errorf("%s = %v, want 0. If the underlying metric gained a service "+
				"label, this limitation is over -- update GetServiceGoldenSignals "+
				"and delete this expectation rather than relaxing it", tc.name, tc.got)
		}
	}
}
