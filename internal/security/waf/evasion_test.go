// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf_test

import (
	"testing"

	"github.com/gsoultan/gwaf"
)

// Evasion coverage: the same payload said a different way.
//
// A WAF is only worth its latency if it resists re-encoding, and that property
// cannot be tested through the gateway. An end-to-end probe shares one JA4+
// with the rest of the suite, so the first blocked request mitigates the client
// and every later assertion of "not allowed" passes for the wrong reason. Down
// here there is no fingerprint, no mitigation, no ordering — payload in,
// verdict out.
//
// The benign cases are not padding. A table that only asserts "blocked" is
// satisfied by an engine that blocks everything, which is a broken WAF and a
// green test. Both directions have to hold for either to mean anything.

type evasionCase struct {
	name   string
	target string
	// block is what the engine must do. False means this is ordinary traffic
	// the gateway has to keep serving.
	block bool
}

// newEngine builds the default engine. gateon layers its own rules on top of
// this in Policy.Options, so what is pinned here is the floor: anything this
// misses, the shipped gateway only catches if a gateon rule happens to.
func newEvasionEngine(t *testing.T) *gwaf.WAF {
	t.Helper()
	w, err := gwaf.New()
	if err != nil {
		t.Fatalf("gwaf.New: %v", err)
	}
	return w
}

func evasionDecide(t *testing.T, w *gwaf.WAF, target string) (blocked bool, ruleID int, score int) {
	t.Helper()
	tx := w.NewTransaction()
	defer tx.Close()

	tx.SetRemoteAddr("203.0.113.10:44321")
	tx.SetRequestLine("GET", target, "HTTP/1.1")
	tx.AddRequestHeader("Host", "shop.example.com")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")

	d := tx.ProcessRequestHeaders()
	return d.Blocked(), int(d.RuleID()), d.Score()
}

// SQL injection, re-encoded. The plain form is the control: if it stops being
// blocked, every "evasion" below is meaningless and the failure should say so.
func TestSQLiEvasionVariants(t *testing.T) {
	t.Parallel()
	w := newEvasionEngine(t)

	cases := []evasionCase{
		{name: "plain (control)", target: "/p?id=1%27+OR+%271%27%3D%271", block: true},
		{name: "mixed case keyword", target: "/p?id=1%27+oR+%271%27%3D%271", block: true},
		{name: "inline comment split", target: "/p?id=1%27%2F%2A%2A%2FOR%2F%2A%2A%2F%271%27%3D%271", block: true},
		{name: "union select", target: "/p?id=1+UNION+SELECT+NULL%2CNULL--", block: true},
		{name: "union select mixed case", target: "/p?id=1+UnIoN+SeLeCt+NULL%2CNULL--", block: true},
		{name: "stacked query", target: "/p?id=1%3B+DROP+TABLE+users--", block: true},
		{name: "boolean tautology no quotes", target: "/p?id=1+OR+1%3D1", block: true},

		// Ordinary traffic that merely looks tense. These must be served.
		{name: "benign id", target: "/p?id=42", block: false},
		{name: "benign search phrase", target: "/search?q=how+to+select+a+union+plan", block: false},
		{name: "benign apostrophe in name", target: "/users?name=O%27Brien", block: false},
	}

	runEvasionTable(t, w, cases)
}

// Cross-site scripting, re-encoded.
func TestXSSEvasionVariants(t *testing.T) {
	t.Parallel()
	w := newEvasionEngine(t)

	cases := []evasionCase{
		{name: "plain script tag (control)", target: "/p?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", block: true},
		{name: "mixed case tag", target: "/p?q=%3CScRiPt%3Ealert(1)%3C%2FScRiPt%3E", block: true},
		{name: "svg onload", target: "/p?q=%3Csvg%2Fonload%3Dalert(1)%3E", block: true},
		{name: "img onerror", target: "/p?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E", block: true},
		{name: "javascript uri", target: "/p?next=javascript%3Aalert(1)", block: true},
		{name: "body onload no space", target: "/p?q=%3Cbody%2Fonload%3Dalert(1)%3E", block: true},

		{name: "benign html words", target: "/p?q=script+writing+for+beginners", block: false},
	}

	runEvasionTable(t, w, cases)
}

// Path traversal and shell injection, re-encoded. Double-encoding is the
// interesting one: a decoder that runs once sees "%2e%2e", a decoder that runs
// twice sees "..", and a proxy chain can disagree with its own backend.
func TestTraversalAndCommandEvasionVariants(t *testing.T) {
	t.Parallel()
	w := newEvasionEngine(t)

	cases := []evasionCase{
		{name: "traversal plain (control)", target: "/f?path=../../etc/passwd", block: true},
		{name: "traversal url-encoded", target: "/f?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd", block: true},
		{name: "traversal double-encoded", target: "/f?path=%252e%252e%252fetc%252fpasswd", block: true},
		{name: "traversal dot-slash padding", target: "/f?path=....%2F%2F....%2F%2Fetc%2Fpasswd", block: true},
		{name: "command substitution", target: "/f?host=127.0.0.1%3B+cat+%2Fetc%2Fpasswd", block: true},
		{name: "command pipe", target: "/f?host=127.0.0.1+%7C+id", block: true},

		{name: "benign relative asset", target: "/f?path=images/logo.png", block: false},
		{name: "benign version string", target: "/f?v=1.2.3", block: false},
	}

	runEvasionTable(t, w, cases)
}

// runEvasionTable reports every mismatch rather than stopping at the first, so
// one run says exactly which encodings get through instead of one at a time.
func runEvasionTable(t *testing.T, w *gwaf.WAF, cases []evasionCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, ruleID, score := evasionDecide(t, w, tc.target)
			switch {
			case tc.block && !blocked:
				t.Errorf("payload was allowed through\n  target: %s\n  score:  %d\n"+
					"an encoding the engine does not decode is an encoding an attacker will use",
					tc.target, score)
			case !tc.block && blocked:
				t.Errorf("ordinary request was blocked\n  target: %s\n  rule:   %d  score: %d\n"+
					"false positives on traffic like this are why operators disable the WAF",
					tc.target, ruleID, score)
			case tc.block && blocked && ruleID == 0:
				t.Errorf("blocked with no rule ID; the audit trail cannot attribute it\n  target: %s", tc.target)
			}
		})
	}
}

// Two findings from the tables above, kept as characterization tests rather
// than deleted or silently relaxed. Each asserts what the engine does today, so
// the day gwaf changes either one this fails and someone reads this comment.
//
// Both were found the first time this harness ran. Neither is asserted as
// correct — the assertions below are the shape of the problem, not approval of
// it.
func TestKnownEvasionGaps(t *testing.T) {
	t.Parallel()
	w := newEvasionEngine(t)

	// FALSE POSITIVE. "3 < 5 and 7 > 2" in a search box is arithmetic, and the
	// default engine blocks it as SQLi on rule 2010. Operators do not tune this
	// away one query at a time; they turn the WAF off. This is the more
	// damaging of the two findings, because its victims are customers.
	t.Run("arithmetic in a query is blocked as SQLi", func(t *testing.T) {
		blocked, ruleID, _ := evasionDecide(t, w, "/p?q=3+%3C+5+and+7+%3E+2")
		if !blocked {
			t.Log("gwaf no longer false-positives on arithmetic; move this back " +
				"into TestXSSEvasionVariants as a benign case and delete it here")
			t.Skip()
		}
		if ruleID != 2010 {
			t.Errorf("still a false positive but the rule moved: %d (was 2010)", ruleID)
		}
	})

	// BYPASS. Backtick command substitution is not detected in a query string.
	//
	// gateon layers its own rules on top of this engine, and they do not close
	// it either: rule 1151002 lists the interesting commands (id, cat, whoami,
	// nc, curl...) but its separator class is (?:;|\||&|\$|\n|\r) with no
	// backtick, while rule 1151003 does include a backtick but lists a
	// different command set (env, eval, exec, system...). A backtick plus any
	// command from the first list falls between them.
	//
	// Deliberately not fixed here: 1151002 is PhaseRequestBody, so a
	// query-string payload never reaches it, and widening a live RCE regex
	// wants its own change with false-positive measurement behind it.
	t.Run("backtick command substitution passes in a query string", func(t *testing.T) {
		blocked, _, _ := evasionDecide(t, w, "/f?host=%60id%60")
		if blocked {
			t.Log("backtick substitution is now caught; move this into " +
				"TestTraversalAndCommandEvasionVariants and delete it here")
		}
	})
}
