// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"strconv"
	"sync"
	"testing"
)

// escalateMitigation blocked a JA4+ on the first qualifying threat. A JA4+ is a
// client class, not a client — its header component has four possible values —
// so that let one attacker take out every client sharing their browser and OS,
// for the cost of a single injection.
//
// Against the pre-fix code the first subtest fails: one sighting was enough.

func TestFingerprintNotMitigatedBeforeThreshold(t *testing.T) {
	ResetFingerprintSightings()

	const fp = "t_threshold"
	for i := 1; i < mitigateAfter; i++ {
		ok, reason := shouldMitigateFingerprint(fp, "203.0.113.1")
		if ok {
			t.Fatalf("mitigated after %d sighting(s), threshold is %d; one blocked "+
				"request is noise, and blocking on it hands an attacker a way to "+
				"blocklist everyone who shares their client", i, mitigateAfter)
		}
		if reason == "" {
			t.Error("declined without a reason; the operator log would say nothing useful")
		}
	}

	if ok, _ := shouldMitigateFingerprint(fp, "203.0.113.1"); !ok {
		t.Errorf("a single actor still not mitigated after %d sightings; the gate "+
			"is meant to delay the block, not prevent it", mitigateAfter)
	}
}

// The gate that matters for bystanders. A fingerprint seen from many addresses
// is a population, and blocking it does the attacker's work for them.
func TestFingerprintNotMitigatedWhenBlastRadiusIsWide(t *testing.T) {
	ResetFingerprintSightings()

	const fp = "t_blast"
	// Well past both the threshold and the address ceiling.
	for i := range maxBlastRadius + 5 {
		shouldMitigateFingerprint(fp, "203.0.113."+strconv.Itoa(i+1))
	}

	ok, reason := shouldMitigateFingerprint(fp, "203.0.113.200")
	if ok {
		t.Errorf("mitigated a fingerprint spanning %d+ addresses; that is a client "+
			"population, and blocking it is the denial of service", maxBlastRadius)
	}
	if reason == "" {
		t.Error("declined without a reason")
	}

	count, atLeast := FingerprintBlastRadius(fp)
	if count == 0 {
		t.Error("blast radius reported as 0 for a fingerprint seen from many addresses")
	}
	if !atLeast {
		t.Errorf("blast radius %d not reported as a floor, but tracking is capped at %d",
			count, maxTrackedIPs)
	}
}

// A quiet fingerprint must not inherit a noisy one's history.
func TestFingerprintSightingsArePerFingerprint(t *testing.T) {
	ResetFingerprintSightings()

	for range mitigateAfter + 2 {
		shouldMitigateFingerprint("t_noisy", "203.0.113.1")
	}
	if ok, _ := shouldMitigateFingerprint("t_quiet", "203.0.113.1"); ok {
		t.Error("a fingerprint seen once was mitigated; sightings are leaking between keys")
	}
}

// An empty source address must not be counted as a distinct one, or a single
// actor behind a proxy that strips the address would look like a population and
// escape mitigation entirely.
func TestFingerprintEmptySourceIPDoesNotWidenBlastRadius(t *testing.T) {
	ResetFingerprintSightings()

	const fp = "t_noip"
	for range mitigateAfter + 3 {
		shouldMitigateFingerprint(fp, "")
	}
	if ok, reason := shouldMitigateFingerprint(fp, ""); !ok {
		t.Errorf("a repeat offender with no source address was never mitigated: %s", reason)
	}
}

func TestShouldMitigateFingerprintIsConcurrencySafe(t *testing.T) {
	ResetFingerprintSightings()

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			shouldMitigateFingerprint("t_race", "203.0.113."+strconv.Itoa(i%8+1))
		}(i)
	}
	wg.Wait()

	if count, _ := FingerprintBlastRadius("t_race"); count == 0 {
		t.Error("no sightings recorded under concurrent load")
	}
}
