// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mitigation

import (
	"slices"
	"testing"

	"github.com/gsoultan/gateon/internal/security/correlation"
)

// A reputation score belongs to a browser class *on a network* (ADR 0010),
// because JA4+ on its own names a browser build rather than a client and every
// user of that build shares it.
//
// That makes the responder's penalty a scoping problem. It receives an incident
// which may name many addresses — a botnet sharing one fingerprint across a
// hundred hosts is exactly what the correlation engine exists to find — and if it
// penalises the fingerprint alone it writes a key no enforcement site reads, so
// the operator is told the incident was mitigated and nothing was.

// TestDegradeScopesToEveryParticipatingNetwork pins the reach of a penalty.
//
// Every address that appeared in the incident is penalised, and the fingerprint
// is never penalised on its own. This is what keeps the cross-address reach that
// made JA4+ attractive while confining it to addresses that actually took part.
func TestDegradeScopesToEveryParticipatingNetwork(t *testing.T) {
	r, degraded := newTestResponder(Config{Enabled: true}, &fakeShun{})

	r.Handle(correlation.Incident{
		SourceIP:    "203.0.113.7",
		SourceIPs:   []string{"203.0.113.7", "198.51.100.4", "192.0.2.9"},
		Fingerprint: "fp-botnet",
		Severity:    "high",
		SignalTypes: []string{"waf_block", "rate_limit", "scanner_ua"},
	})

	want := []string{
		"fp-botnet@203.0.113.7",
		"fp-botnet@198.51.100.4",
		"fp-botnet@192.0.2.9",
	}
	for _, w := range want {
		if !slices.Contains(*degraded, w) {
			t.Errorf("participant %q was not penalised; got %v\n"+
				"An incident spanning several hosts must degrade each of them, or the "+
				"ones left out keep a clean score while the operator reads that the "+
				"incident was handled.", w, *degraded)
		}
	}

	for _, got := range *degraded {
		if got == "fp-botnet@" {
			t.Errorf("the fingerprint was penalised with no network scope; got %v\n"+
				"That writes a key no enforcement site reads, so the penalty silently "+
				"does nothing.", *degraded)
		}
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

// TestDegradeDeduplicatesRepeatedSources guards against counting one host twice.
//
// SourceIP is normally also present in SourceIPs, so the obvious implementation
// applies the penalty to that host twice and it falls to zero at half the
// intended number of incidents. A penalty schedule that is silently double what
// was configured is how a mitigation tier turns into a block.
func TestDegradeDeduplicatesRepeatedSources(t *testing.T) {
	r, degraded := newTestResponder(Config{Enabled: true}, &fakeShun{})

	r.Handle(correlation.Incident{
		SourceIP:    "203.0.113.7",
		SourceIPs:   []string{"203.0.113.7", "203.0.113.7"},
		Fingerprint: "fp-dupe",
		Severity:    "high",
		SignalTypes: []string{"waf_block", "rate_limit"},
	})

	count := 0
	for _, got := range *degraded {
		if got == "fp-dupe@203.0.113.7" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("one host was penalised %d times, want 1 (got %v)", count, *degraded)
	}
}
