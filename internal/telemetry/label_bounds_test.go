// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// TestMethodLabelFoldsUnknownTokens covers the cheapest of the two attacks by
// bandwidth. Go's server accepts any RFC 7230 token as a method, so
// "ZZQ000001 / HTTP/1.1" is a valid request line -- and an unbounded label
// mints a counter series and a twelve-bucket histogram series for each one, at
// roughly 2.3 KB of permanent heap per token. About 45 MB of traffic exhausted
// a 2 GB host.
func TestMethodLabelFoldsUnknownTokens(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, "PROPFIND"} {
		if got := MethodLabel(m); got != m {
			t.Errorf("MethodLabel(%q) = %q, want it kept: real methods must keep "+
				"their own series or the metric stops being useful", m, got)
		}
	}

	for _, m := range []string{"ZZQ000001", "X", "FROBNICATE", ""} {
		if got := MethodLabel(m); got != LabelOverflow {
			t.Errorf("MethodLabel(%q) = %q, want %q: an invented method token "+
				"is a permanent series a client chose", m, got, LabelOverflow)
		}
	}
}

// TestDomainLabelStopsGrowing measures the ceiling rather than asserting one
// exists. The Host header is attacker-chosen and costs three permanent series
// per distinct value; 200,000 of them measured at 275.8 MiB before this bound.
func TestDomainLabelStopsGrowing(t *testing.T) {
	b := &boundedLabels{max: 100}

	// Fill the budget with "real" domains.
	for i := range 100 {
		d := "tenant" + strconv.Itoa(i) + ".example"
		if got := b.value(d); got != d {
			t.Fatalf("value(%q) = %q while under the cap", d, got)
		}
	}

	// Everything past it folds.
	distinct := map[string]struct{}{}
	for i := range 10_000 {
		distinct[b.value("attacker"+strconv.Itoa(i)+".example")] = struct{}{}
	}
	if len(distinct) != 1 {
		t.Errorf("10,000 novel domains past the cap produced %d distinct labels, "+
			"want 1: the bound is not bounding", len(distinct))
	}
	for d := range distinct {
		if d != LabelOverflow {
			t.Errorf("overflow label = %q, want %q", d, LabelOverflow)
		}
	}

	// The ones admitted first are still reported individually: an attacker
	// must not be able to displace the domains an operator actually watches.
	if got := b.value("tenant7.example"); got != "tenant7.example" {
		t.Errorf("an already-admitted domain folded to %q after the cap was "+
			"reached; attacker traffic displaced real traffic", got)
	}
}

func TestDomainLabelHandlesEmpty(t *testing.T) {
	if got := DomainLabel(""); got != labelUnknown {
		t.Errorf("DomainLabel(\"\") = %q, want %q", got, labelUnknown)
	}
}

// TestFirstRuleIDReducesAnAttackerChosenCombination covers the WAF metric
// label. TriggeredRules is the JSON array of *every* rule a request matched,
// and an attacker picks the combination by choosing which tokens to put in one
// payload -- so the label declared rule_id was really
// rule_id_combination, one permanent series per blocked request.
func TestFirstRuleIDReducesAnAttackerChosenCombination(t *testing.T) {
	cases := map[string]string{
		`["942100"]`:                   "942100",
		`["942100","941100","930110"]`: "942100",
		`["942100","941100"]`:          "942100",
		`[]`:                           "",
		``:                             "",
		`not json`:                     "",
	}
	for in, want := range cases {
		if got := firstRuleID(in); got != want {
			t.Errorf("firstRuleID(%q) = %q, want %q", in, got, want)
		}
	}

	// The property that matters: distinct combinations sharing a first rule
	// collapse to one label.
	a := firstRuleID(`["942100","941100"]`)
	b := firstRuleID(`["942100","930110","941100"]`)
	if a != b {
		t.Errorf("two combinations of the same first rule produced %q and %q; "+
			"an attacker still mints a series per payload shape", a, b)
	}
}

// TestLabelValuesAreBoundedInLengthNotJustCount covers the axis the first
// bounding pass missed.
//
// Capping how many distinct values are retained does nothing about how large
// each one is, and nothing in this tree limits the length of a URI, a Host or
// a path: there is no StatusRequestURITooLong anywhere, and the header budget
// is 1 MiB. So a single request can carry a 200 KB Host, and 2,000 of those
// is about 400 MB pinned for the life of the process -- against the 1,446 B
// per value this code originally claimed, a 275x error.
func TestLabelValuesAreBoundedInLengthNotJustCount(t *testing.T) {
	huge := strings.Repeat("a", 200*1024) + ".example"

	got := DomainLabel(huge)
	if len(got) > maxLabelValueBytes+1 {
		t.Errorf("DomainLabel returned %d bytes for a 200KB host; the count cap "+
			"bounds how many values are kept, not how big each one is", len(got))
	}

	// A real hostname must survive untouched -- 253 is the DNS maximum, so
	// only a fabricated value is ever cut.
	real := "api.customer-tenant-seventeen.example.com"
	if got := DomainLabel(real); got != real {
		t.Errorf("DomainLabel(%q) = %q; a legitimate hostname was truncated", real, got)
	}

	// And the truncation is marked, so a reader can tell a cut value from a
	// genuinely odd one.
	if !strings.HasSuffix(DomainLabel(huge), "~") {
		t.Error("a truncated label is not marked; it reads as a real domain that " +
			"happens to be 253 characters long")
	}
}
