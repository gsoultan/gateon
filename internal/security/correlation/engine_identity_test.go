// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package correlation

import (
	"slices"
	"testing"
	"time"
)

// stockChrome is a JA4+ every user of one browser build presents: it names the
// software, not the person (ADR 0011, 0024).
const stockChrome = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"

// TestABrowserClassOnTwoNetworksIsNotOneIncident is TRUTH-NEW-1 at the engine.
//
// An attacker on one network and a user of the same browser build on another
// share a fingerprint and nothing else. Grouped by fingerprint, the attacker's
// blocks and one detection against the user made one incident with two distinct
// signal types -- enough for the responder to act -- whose source was the user.
func TestABrowserClassOnTwoNetworksIsNotOneIncident(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	var incidents []Incident
	e := newTestEngine(Config{
		Window: time.Minute, MinSignals: 3,
		OnIncident: func(inc Incident) { incidents = append(incidents, inc) },
	}, &now)

	e.Observe(Signal{Type: "waf_detected", SourceIP: "203.0.113.10", Fingerprint: stockChrome, Time: now})
	e.Observe(Signal{Type: "waf_blocked", SourceIP: "198.18.5.5", Fingerprint: stockChrome, Time: now})
	e.Observe(Signal{Type: "waf_blocked", SourceIP: "198.18.5.5", Fingerprint: stockChrome, Time: now})

	for _, inc := range incidents {
		if slices.Contains(inc.SourceIPs, "203.0.113.10") {
			t.Fatalf("an incident names 203.0.113.10, which only shares a browser build with the attacker: %+v", inc)
		}
	}
	if len(incidents) != 0 {
		t.Fatalf("%d incidents from two signals on one network and one on another, want 0: %+v", len(incidents), incidents)
	}
}

// TestOneClassOnOneNetworkStillCorrelates is the other half: a client
// changing address inside its /24, or several machines of one build behind one
// network, are still one source -- the reach a JA4+ is good for.
func TestOneClassOnOneNetworkStillCorrelates(t *testing.T) {
	now := time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)
	e := newTestEngine(Config{Window: time.Minute, MinSignals: 3}, &now)

	e.Observe(Signal{Type: "waf_blocked", SourceIP: "198.18.5.5", Fingerprint: stockChrome, Time: now})
	e.Observe(Signal{Type: "honeypot_triggered", SourceIP: "198.18.5.6", Fingerprint: stockChrome, Time: now})
	inc, fired := e.Observe(Signal{Type: "waf_blocked", SourceIP: "198.18.5.7", Fingerprint: stockChrome, Time: now})
	if !fired {
		t.Fatal("three signals from one build on one /24 did not open an incident")
	}
	if want := []string{"198.18.5.5", "198.18.5.6", "198.18.5.7"}; !slices.Equal(inc.SourceIPs, want) {
		t.Errorf("incident participants %v, want %v", inc.SourceIPs, want)
	}
}

// TestAFingerprintWithNoAddressIsNotCorrelated: with no address there is no
// network to hold a signal against, and one bucket for every address-less
// client of a build would be the class-wide grouping again.
func TestAFingerprintWithNoAddressIsNotCorrelated(t *testing.T) {
	e := New(Config{MinSignals: 1})
	if _, fired := e.Observe(Signal{Type: "waf_blocked", Fingerprint: stockChrome}); fired {
		t.Fatal("a signal with a fingerprint and no address opened an incident")
	}
	if got := e.TrackedSources(); got != 0 {
		t.Fatalf("tracked sources = %d, want 0", got)
	}
}
