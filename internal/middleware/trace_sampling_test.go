// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
)

// Trace recording clones both header maps and persists a blob per request. It
// measured 208 B and 7 allocations against a 610 B / 7 allocation infrastructure
// chain — so it roughly doubled the allocation count of every proxied request —
// and it recorded every request by default on every tier, including the tier
// whose trace store is closed and drops the result on the floor.
//
// Sampling fixes the cost and introduces a new way to be wrong: an operator opens
// the trace view because something failed, and a 1-in-20 sample of failures means
// the request they came to find is usually missing. That is worse than not
// sampling, because the view still looks complete.

// TestFailuresAreTracedRegardlessOfSampling is the property that makes sampling
// safe to turn on.
//
// A sampled rate applies to requests that succeeded. 4xx is kept alongside 5xx
// deliberately: a 403 is what a false positive looks like from outside, and the
// whole false-positive effort depends on those being visible rather than sampled
// away.
func TestFailuresAreTracedRegardlessOfSampling(t *testing.T) {
	var counter uint64

	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	} {
		// Repeat so a case that only passed on the counter's Nth tick is caught.
		for range 5 {
			if !shouldRecordTrace(20, &counter, status) {
				t.Errorf("status %d was not traced at a 1-in-20 rate.\n"+
					"Failures are why anyone opens the trace view; sampling them away "+
					"leaves a view that looks complete and is missing the request "+
					"someone is looking for.", status)
			}
		}
	}
}

// TestSuccessfulRequestsAreSampled is the other half: the saving has to be real.
func TestSuccessfulRequestsAreSampled(t *testing.T) {
	var counter uint64

	const rate, requests = 20, 2000
	recorded := 0
	for range requests {
		if shouldRecordTrace(rate, &counter, http.StatusOK) {
			recorded++
		}
	}

	if recorded != requests/rate {
		t.Errorf("recorded %d of %d successful requests at a 1-in-%d rate, want %d",
			recorded, requests, rate, requests/rate)
	}
}

// TestTraceRateZeroRecordsNothing pins the explicit opt-out.
//
// Zero means zero, including failures. An operator who set the rate to zero — or
// who is on the minimal tier, chosen for its memory ceiling — asked for no
// traces, and quietly keeping some would be a surprise on exactly the deployment
// least able to absorb it.
func TestTraceRateZeroRecordsNothing(t *testing.T) {
	var counter uint64
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError} {
		if shouldRecordTrace(0, &counter, status) {
			t.Errorf("status %d was traced with the rate set to 0", status)
		}
	}
}

// TestTraceRateOneRecordsEverything pins the enterprise setting.
func TestTraceRateOneRecordsEverything(t *testing.T) {
	var counter uint64
	for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusForbidden} {
		if !shouldRecordTrace(1, &counter, status) {
			t.Errorf("status %d was not traced with the rate set to 1", status)
		}
	}
}

// TestTraceSampleRateFollowsTier pins the per-tier defaults.
//
// Minimal is 0: its trace store is closed, so the rate used to make it clone two
// header maps per request and throw the result away at recordTraceToStore.
// Removing that changes nothing anyone can observe.
//
// Standard and enterprise are both 1, which is what every existing install
// already does. Turning standard down would save roughly 7 allocations per
// request and would also stop the trace view showing every successful request —
// a default change that re-prices every deployment relying on it, so it is an
// operator decision rather than one taken here. This test exists so that
// decision has to be made deliberately rather than drifting.
func TestTraceSampleRateFollowsTier(t *testing.T) {
	cases := []struct {
		tier config.Tier
		want uint32
	}{
		{config.TierMinimal, 0},
		{config.TierStandard, 1},
		{config.TierEnterprise, 1},
	}
	for _, tc := range cases {
		if got := config.DefaultsFor(tc.tier).TraceSampleRate; got != tc.want {
			t.Errorf("%s tier trace sample rate is %d, want %d", tc.tier, got, tc.want)
		}
	}
}

// TestTraceSampleRateEnvOverridesTier keeps the escape hatch working.
//
// Every tunable needs an env-var path (AGENTS.md), and this one is how an
// operator debugging a live incident turns full tracing on without changing tier
// and restarting into a different memory profile.
func TestTraceSampleRateEnvOverridesTier(t *testing.T) {
	t.Setenv("GATEON_PROFILE", string(config.TierStandard))

	t.Setenv("GATEON_TRACE_SAMPLE_RATE", "1")
	if got := traceSampleRate(); got != 1 {
		t.Errorf("env override gave %d, want 1 — an operator cannot raise tracing "+
			"for an incident without it", got)
	}

	t.Setenv("GATEON_TRACE_SAMPLE_RATE", "0")
	if got := traceSampleRate(); got != 0 {
		t.Errorf("env override gave %d, want 0", got)
	}
}

// TestTraceSampleRateRejectsGarbageSafely pins the direction of the failure.
//
// A malformed value falls back to recording everything, not to recording
// nothing. This is an observability knob: a typo that silently disables tracing
// is discovered during an incident, which is the worst possible moment.
func TestTraceSampleRateRejectsGarbageSafely(t *testing.T) {
	t.Setenv("GATEON_TRACE_SAMPLE_RATE", "not-a-number")
	if got := traceSampleRate(); got != 1 {
		t.Errorf("a malformed rate resolved to %d, want 1 — a typo must not "+
			"silently switch tracing off", got)
	}
}
