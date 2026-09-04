// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// gwaf compiles every rule and then reports which of them cannot detect what
// their name implies — a rule that says "Shellshock" but only ever inspects the
// query string, for instance, so a Shellshock attempt in a form body walks past
// it. `Diagnostics()` returns that list, and an empty list is the healthy answer.
//
// Gateon already logged these, at warn, once per engine build. That was not
// enough, and the reason is worth stating: a warning at startup is read once, by
// whoever happened to be looking at the terminal on the day it first appeared.
// It was in fact being emitted on every single engine build in this repo, and it
// took reading unrelated benchmark output to notice it.
//
// A coverage gap that nobody is told about twice is a coverage gap nobody fixes.
// So it is a test: every diagnostic must either be gone or be written down here
// with a reason, and a new one fails the build.

// acknowledgedDiagnostics are the rules known to be narrower than they look,
// each with the reason it is acceptable.
//
// Adding an entry is a deliberate act and should be uncomfortable. Each one is a
// rule that will not fire where a reader of its name would expect it to, so the
// reason has to say why that is tolerable — not merely that it is true.
var acknowledgedDiagnostics = map[uint32]string{
	1100014: "Shellshock (CVE-2014-6271), header phase only. Deliberate, and " +
		"documented at its ruleset.go entry: the body half is carried by a " +
		"separate rule, and Shellshock is a header attack — the payload goes " +
		"in User-Agent or Cookie, not in a JSON body.",

	1150001: "Null byte injection, header phase only. A null byte is an attack " +
		"where it truncates a string a downstream parser treats as a path or a " +
		"filename, which reaches the server through the URI and the query, both " +
		"of which this rule does inspect. A raw NUL inside a JSON body is not " +
		"valid JSON in the first place, so the uncovered case is narrower than " +
		"the rule name suggests.",

	1007: "CRLF header injection, header phase only, PL2. The attack is a value " +
		"that gets reflected into a response header, and the values applications " +
		"reflect that way arrive in the query string, the path or a request " +
		"header — all inspected. A CRLF sequence inside a JSON body would have " +
		"to be decoded and re-emitted into a header to matter, which is a " +
		"different bug in the application than the one this rule describes.",
}

// TestNoUnacknowledgedRuleDiagnostics fails when gwaf reports a rule that cannot
// detect what it claims and nobody has written down why that is acceptable.
//
// Both paranoia levels are checked because the ruleset differs between them: a
// rule admitted only at PL2 cannot produce a diagnostic at PL1, so testing one
// level would leave the other unguarded.
func TestNoUnacknowledgedRuleDiagnostics(t *testing.T) {
	for _, pl := range []int{1, 2} {
		t.Run(fmt.Sprintf("PL%d", pl), func(t *testing.T) {
			// Origins are declared because a deployment declares them. Without
			// them the off-origin rules (1013, 1913) correctly report that they
			// can detect nothing, and those diagnostics would be an artifact of
			// the test's own configuration rather than a property of the ruleset.
			// TestNoOriginsIsReportedAsACoverageGap covers that case on purpose.
			w, err := Policy{
				ParanoiaLevel: pl,
				Origins:       []string{"app.example.com"},
			}.NewEngine()
			if err != nil {
				t.Fatalf("build engine at PL%d: %v", pl, err)
			}

			var unexpected []string
			for _, d := range w.Diagnostics() {
				if _, ok := acknowledgedDiagnostics[uint32(d.ID)]; ok {
					continue
				}
				unexpected = append(unexpected, fmt.Sprintf(
					"  rule %d %q\n    cannot: %s\n    fix:    %s",
					uint32(d.ID), d.Msg, d.Reason, d.Fix))
			}

			if len(unexpected) > 0 {
				sort.Strings(unexpected)
				t.Errorf("gwaf reports %d rule(s) that cannot detect what their names "+
					"imply, and none of them is acknowledged:\n%s\n\n"+
					"Each of these is a rule that will not fire where someone reading "+
					"its name would expect it to. Either apply the stated fix, or add "+
					"the rule to acknowledgedDiagnostics with the reason the gap is "+
					"acceptable. Do not add it without one — an unexplained entry is "+
					"the same silence this test replaced.",
					len(unexpected), strings.Join(unexpected, "\n"))
			}
		})
	}
}

// TestAcknowledgedDiagnosticsStillApply keeps the acknowledgement list honest in
// the other direction.
//
// A rule listed here that gwaf no longer complains about has been fixed — either
// upstream or in gateon's ruleset — and leaving the entry behind means the next
// person reads a coverage gap that does not exist, and may decline to rely on a
// rule that now works perfectly well. It is the same ratchet the false-positive
// corpus uses: a record that outlives its cause becomes misinformation.
func TestAcknowledgedDiagnosticsStillApply(t *testing.T) {
	seen := make(map[uint32]bool)
	for _, pl := range []int{1, 2} {
		w, err := Policy{
			ParanoiaLevel: pl,
			Origins:       []string{"app.example.com"},
		}.NewEngine()
		if err != nil {
			t.Fatalf("build engine at PL%d: %v", pl, err)
		}
		for _, d := range w.Diagnostics() {
			seen[uint32(d.ID)] = true
		}
	}

	for id, reason := range acknowledgedDiagnostics {
		if !seen[id] {
			t.Errorf("rule %d is acknowledged as narrower than it looks, but gwaf no "+
				"longer reports it at either paranoia level.\n"+
				"  recorded reason: %s\n"+
				"Remove the entry. A gap that has been closed but is still written "+
				"down will be believed.", id, reason)
		}
	}
}

// TestNoOriginsIsReportedAsACoverageGap pins the warning an operator depends on.
//
// gwaf's off-origin rules report nothing when no origins are declared, because
// the only other candidate — the request's own Host header — is written by the
// attacker (mem:gwaf_v040: comparing against it was itself the bypass). An
// install that never configured origins therefore has no open-redirect and no
// SSRF coverage, and both rules still appear in the ruleset, so the policy
// *reads* as protected.
//
// The only thing standing between that and a silent hole is this diagnostic. If
// gwaf ever stops emitting it, the gap becomes invisible again, and this test is
// what notices.
func TestNoOriginsIsReportedAsACoverageGap(t *testing.T) {
	w, err := Policy{ParanoiaLevel: 1}.NewEngine()
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}

	found := map[uint32]bool{}
	for _, d := range w.Diagnostics() {
		found[uint32(d.ID)] = true
	}

	for _, id := range []uint32{1013, 1913} {
		if !found[id] {
			t.Errorf("rule %d reported no diagnostic on a policy with no origins.\n"+
				"Either it now works without them — in which case this expectation "+
				"should be updated deliberately — or the one signal telling an "+
				"operator they have no open-redirect coverage has gone quiet.", id)
		}
	}
}
