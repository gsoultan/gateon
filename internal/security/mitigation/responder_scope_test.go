// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mitigation

import (
	"slices"
	"testing"

	"github.com/gsoultan/gateon/internal/security/correlation"
)

// A reputation score belongs to a browser class *on a network* (ADR 0011),
// because JA4+ on its own names a browser build rather than a client and every
// user of that build shares it.
//
// That makes the responder's penalty a scoping problem. If it penalises the
// fingerprint alone it writes a key no enforcement site reads, so the operator
// is told the incident was mitigated and nothing was; if it penalises every
// network a fingerprint was seen on, it refuses everyone who runs the build.
// The penalty lands on the source's class on the source's network, once.

// TestAnIncidentPenalisesOnlyItsSourcesNetwork is TRUTH-NEW-1 at the responder
// (ADR 0055).
//
// It used to penalise every address the incident named, on every network. When
// the engine grouped by browser class alone, those were unrelated clients that
// shared a build with the attacker, and a bystander on a victim's /24 got 403
// for traffic it never sent. An incident handed over naming other networks --
// from an engine that still grouped that way -- must reach the source's network
// and no other.
func TestAnIncidentPenalisesOnlyItsSourcesNetwork(t *testing.T) {
	r, degraded := newTestResponder(Config{Enabled: true}, &fakeShun{})

	r.Handle(correlation.Incident{
		SourceIP:    "203.0.113.7",
		SourceIPs:   []string{"203.0.113.7", "198.51.100.4", "192.0.2.9"},
		Fingerprint: "fp-shared-build",
		Severity:    "high",
		SignalTypes: []string{"waf_blocked", "honeypot_triggered"},
	})

	if want := []string{"fp-shared-build@203.0.113.7"}; !slices.Equal(*degraded, want) {
		t.Errorf("penalised %v, want %v\n"+
			"A browser-class match on another network is context, never a reason to act: "+
			"those addresses only run the same build as the incident's source.", *degraded, want)
	}
}

// TestAnIncidentWithNoAddressPenalisesNobody: with no address there is no
// network, and the class's unknown-network bucket is every address-less client
// of the build at once.
func TestAnIncidentWithNoAddressPenalisesNobody(t *testing.T) {
	r, degraded := newTestResponder(Config{Enabled: true}, &fakeShun{})

	r.Handle(correlation.Incident{
		Fingerprint: "fp-nowhere",
		Severity:    "high",
		SignalTypes: []string{"waf_blocked", "honeypot_triggered"},
	})

	if len(*degraded) != 0 {
		t.Errorf("an incident with no address penalised %v", *degraded)
	}
}

// TestDegradeDoesNotPenaliseBystanders is the property the whole scoping change
// exists for, expressed at the responder.
//
// A client that shares the incident's fingerprint but never appeared in it must
// not be touched. Before scoping, degrading "fp-shared" reached every client
// running that browser anywhere.
func TestDegradeDoesNotPenaliseBystanders(t *testing.T) {
	r, degraded := newTestResponder(Config{Enabled: true}, &fakeShun{})

	r.Handle(correlation.Incident{
		SourceIP:    "203.0.113.7",
		SourceIPs:   []string{"203.0.113.7"},
		Fingerprint: "fp-shared",
		Severity:    "high",
		SignalTypes: []string{"waf_block", "rate_limit"},
	})

	for _, got := range *degraded {
		if got != "fp-shared@203.0.113.7" {
			t.Errorf("penalty reached %q, which did not appear in the incident; "+
				"got %v", got, *degraded)
		}
	}
	if len(*degraded) == 0 {
		t.Error("the participating source was not penalised at all")
	}
}

// TestAnIncidentOnOneNetworkIsPenalisedOnce guards against counting one score
// several times.
//
// Every participant of an incident is on its source's network, and a score is
// kept per class on a network, so a penalty per participant took the same
// score down once per address: three machines of one build behind one /24
// cost three times the configured penalty, and a mitigation tier became a
// block.
func TestAnIncidentOnOneNetworkIsPenalisedOnce(t *testing.T) {
	r, degraded := newTestResponder(Config{Enabled: true}, &fakeShun{})

	r.Handle(correlation.Incident{
		SourceIP:    "203.0.113.7",
		SourceIPs:   []string{"203.0.113.7", "203.0.113.8", "203.0.113.9", "203.0.113.7"},
		Fingerprint: "fp-office",
		Severity:    "high",
		SignalTypes: []string{"waf_blocked", "honeypot_triggered"},
	})

	if len(*degraded) != 1 {
		t.Errorf("one network's score was penalised %d times, want 1 (got %v)", len(*degraded), *degraded)
	}
}
