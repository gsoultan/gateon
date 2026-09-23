// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package correlation

import (
	"strings"
	"testing"
	"time"
)

// TestObserveBoundsRetainedSignalStrings: the engine bounds how many signals it
// keeps (MaxSources x MaxSignalsPerSource) but nothing bounded how large each
// one is, and RequestURI comes off the wire. A client that can put 200 KB in a
// URI can put it in every retained slot.
func TestObserveBoundsRetainedSignalStrings(t *testing.T) {
	e := New(Config{MinSignals: 99, Window: time.Hour})

	const oversized = 200 << 10
	huge := strings.Repeat("A", oversized)

	e.Observe(Signal{
		Type:       "sqli",
		SourceIP:   "203.0.113.5",
		RequestURI: "/" + huge,
		Details:    huge,
		Time:       time.Now(),
	})

	e.mu.Lock()
	st := e.sources["203.0.113.5"]
	e.mu.Unlock()

	if st == nil || len(st.signals) != 1 {
		t.Fatalf("expected one retained signal, got %+v", st)
	}
	got := st.signals[0]

	if len(got.RequestURI) > maxSignalURIBytes+1 {
		t.Errorf("retained RequestURI is %d bytes, want at most %d; a single "+
			"request can size every slot the window holds",
			len(got.RequestURI), maxSignalURIBytes+1)
	}
	if len(got.Details) > maxSignalDetailsBytes+1 {
		t.Errorf("retained Details is %d bytes, want at most %d",
			len(got.Details), maxSignalDetailsBytes+1)
	}
	// Truncation must be visible, not silent: a reader has to be able to tell a
	// bounded value from one that was simply short.
	if !strings.HasSuffix(got.RequestURI, "~") {
		t.Error("a truncated RequestURI is not marked, so it reads as the whole URI")
	}
}

// TestObserveLeavesOrdinarySignalsIntact is the positive control: the bound
// must not rewrite values that were already within it.
func TestObserveLeavesOrdinarySignalsIntact(t *testing.T) {
	e := New(Config{MinSignals: 99, Window: time.Hour})

	const uri = "/admin/login?next=%2Fdashboard"
	const details = "3 failed credential attempts"
	e.Observe(Signal{
		Type:       "bruteforce",
		SourceIP:   "203.0.113.6",
		RequestURI: uri,
		Details:    details,
		Time:       time.Now(),
	})

	e.mu.Lock()
	st := e.sources["203.0.113.6"]
	e.mu.Unlock()

	if st == nil || len(st.signals) != 1 {
		t.Fatalf("expected one retained signal, got %+v", st)
	}
	if got := st.signals[0]; got.RequestURI != uri || got.Details != details {
		t.Errorf("an ordinary signal was rewritten: URI=%q details=%q", got.RequestURI, got.Details)
	}
}
