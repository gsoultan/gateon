// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"net/url"
	"testing"

	"github.com/gsoultan/gwaf/ruleset/leaks"
	"github.com/gsoultan/gwaf/ruleset/signatures"
	"github.com/gsoultan/gwaf/types"
)

// definedByGateon is every built-in rule whose detection is written in this
// repository. Each is here for a reason gwaf's scope line gives: it reads a
// decision gateon made and handed over through a resolver, or it states what
// this site allows rather than what an attack looks like. Adding to this list
// is an architectural decision (ADR 0093), which is why it is a list in a test
// and not a property the table can grant itself.
var definedByGateon = map[uint32]string{
	1210001: "content policy: gambling keywords are not an attack",
	1910001: "reads gateon's reputation bucket through a resolver",
	1910002: "reads gateon's reputation bucket through a resolver",
	1150000: "site policy: how deep a request path may go",
	1100001: "reads gateon's admin-access decision through a resolver",
	1100002: "reads gateon's admin-access decision through a resolver",
	1110003: "site policy: whether scripted clients are welcome",
	1180000: "reads gateon's origin decision through a resolver",
}

// TestNoDetectionIsDefinedInGateon keeps detection in gwaf. The table used to
// hold a hundred rules written out in full, and each one was detection a second
// embedder could not have and gwaf's calibration gate never saw. An entry now
// either names the gwaf rule it loads or is on the short list above.
func TestNoDetectionIsDefinedInGateon(t *testing.T) {
	t.Parallel()

	seen := 0
	for _, s := range builtinSpecs {
		if s.from == 0 {
			if _, ok := definedByGateon[s.id]; !ok {
				t.Errorf("rule %d defines its own detection; move the detection to gwaf and name it with from:, "+
					"or add the rule to definedByGateon with the reason gwaf cannot own it", s.id)
			}
			seen++
			continue
		}
		if _, ok := definedByGateon[s.id]; ok {
			t.Errorf("rule %d is listed as defined by gateon but takes its detection from gwaf rule %d", s.id, s.from)
		}
		if s.op != nil || s.targets != nil || s.xform != nil || s.phase != 0 || s.severity != 0 || s.msg != "" {
			t.Errorf("rule %d names gwaf rule %d and also writes detection fields; "+
				"resolveSpecs would overwrite them, so the entry says something that is not true", s.id, s.from)
		}
	}
	if seen != len(definedByGateon) {
		t.Errorf("definedByGateon lists %d rules, the table defines %d", len(definedByGateon), seen)
	}
}

// TestEveryGwafBundleRuleIsLoaded is the other direction. A rule added to one
// of gwaf's bundles does nothing here until the table names it, and a version
// bump that quietly left new detection unloaded would look exactly like one
// that loaded it.
func TestEveryGwafBundleRuleIsLoaded(t *testing.T) {
	t.Parallel()

	named := make(map[types.RuleID]uint32)
	for _, s := range builtinSpecs {
		if s.from == 0 {
			continue
		}
		if prev, dup := named[s.from]; dup {
			t.Errorf("gwaf rule %d is loaded twice, as %d and %d", s.from, prev, s.id)
		}
		named[s.from] = s.id
	}
	for _, r := range append(signatures.All(), leaks.All()...) {
		if _, ok := named[r.ID]; !ok {
			t.Errorf("gwaf rule %d (%s) is not loaded by any built-in rule; give it an ID, a category and a level", r.ID, r.Msg)
		}
	}
}

// TestResolvedSpecsCarryGwafDetection pins what resolveSpecs copies, so that a
// field added to the copy is a field this test was made to know about.
func TestResolvedSpecsCarryGwafDetection(t *testing.T) {
	t.Parallel()

	source := make(map[types.RuleID]types.Confidence)
	for _, r := range append(signatures.All(), leaks.All()...) {
		source[r.ID] = r.Confidence
	}
	for i, s := range defaultSpecs {
		if s.from == 0 {
			continue
		}
		if s.op == nil || len(s.targets) == 0 || s.phase == 0 || s.msg == "" {
			t.Errorf("rule %d came out of resolveSpecs without detection", s.id)
		}
		want := builtinSpecs[i].conf
		if want == 0 {
			want = source[s.from]
		}
		if s.conf != want {
			t.Errorf("rule %d: confidence %v, want %v", s.id, s.conf, want)
		}
	}
}

// TestRetiredAsNativeIsStillRefusedByCore holds the one retirement made when
// detection moved to gwaf to the claim it was made on. Rule 1141001 matched the
// opening of seven embedding tags and was dropped because gwaf's core refuses
// each of them once it carries an attribute. The gateon XSS rules are switched
// off here so that the refusal can only be core's.
func TestRetiredAsNativeIsStillRefusedByCore(t *testing.T) {
	t.Parallel()

	p := Policy{ParanoiaLevel: 2, DisabledCategories: map[string]bool{CategoryXSS: true}}
	w, err := p.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	payloads := []string{
		"<svg onload=alert(1)>", "<svg onload=alert(1)", // unterminated: the page supplies the bracket
		"<iframe src=//evil.example/x>", "<iframe src=//evil.example/x",
		"<object data=//evil.example/x>", "<embed src=//evil.example/x",
		"<base href=//evil.example/>", "<base href=//evil.example/",
		"<applet code=x>", "<meta http-equiv=refresh content=0;url=//evil.example>",
	}
	for _, v := range payloads {
		fired := runAttack(t, w, attack{target: "/?q=" + url.QueryEscape(v)})
		if len(fired) == 0 {
			t.Errorf("nothing refused %q with rule 1141001 retired", v)
		}
		for id := range fired {
			if id >= 1_000_000 {
				t.Errorf("%q was refused by gateon rule %d, so this test did not isolate core", v, id)
			}
		}
	}
}
