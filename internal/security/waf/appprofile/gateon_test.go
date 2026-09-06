// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package appprofile

import (
	"testing"

	"github.com/gsoultan/gwaf/types"
)

// Contributing gateon's own rules to an app profile is the change most likely to
// turn a scoped exception into a way of switching detection off, so it is tested
// the same way the gwaf half already is.

// TestGateonProfileRulesAreScopedNotAGlobalOff is the property the whole
// mechanism rests on.
//
// Every exception gateon contributes must name a rule, a path, a target and a
// field. An entry missing any of those widens to "this rule, everywhere", which
// is what a profile is specifically not allowed to be — and it would read, in a
// config file, exactly like the narrow thing it is not.
func TestGateonProfileRulesAreScopedNotAGlobalOff(t *testing.T) {
	for profile := range gateonRules {
		for _, e := range GateonExceptions(profile) {
			switch {
			case e.RuleID == 0:
				t.Errorf("%s: an exception names no rule, so it suppresses every rule", profile)
			case e.Path == "":
				t.Errorf("%s: rule %d is exempt on every path", profile, e.RuleID)
			case e.Target == types.TargetInvalid:
				t.Errorf("%s: rule %d is exempt on every target, not just parsed "+
					"arguments — that reaches the URI and the headers too",
					profile, e.RuleID)
			case e.Key == "":
				t.Errorf("%s: rule %d is exempt on every field of %q, which is far "+
					"broader than the stored-content field the profile is about",
					profile, e.RuleID, e.Path)
			case e.Note == "":
				t.Errorf("%s: rule %d carries no rationale; an exception with no "+
					"stated reason is indistinguishable from a mistake six months "+
					"later", profile, e.RuleID)
			}
		}
	}
}

// TestGateonProfileRulesAreScopeable pins that these travel through the same
// re-pointing the gwaf half does.
//
// gwaf's shipped paths are Jira's, so an exception left at its default does
// nothing for a paste service on /pastes. ApplyScope re-points
// only entries that carry a Key, so a gateon contribution written without one
// would silently keep Jira's path and quietly do nothing — the exact failure the
// scoping work existed to fix.
func TestGateonProfileRulesAreScopeable(t *testing.T) {
	in := GateonExceptions(IssueTracker)
	if len(in) == 0 {
		t.Fatal("the issue_tracker profile contributes no gateon rules; this test " +
			"would pass vacuously")
	}

	out, err := ApplyScope(in, Scope{
		Paths:  []string{"/pastes"},
		Fields: []string{"content"},
	})
	if err != nil {
		t.Fatalf("scope rejected: %v", err)
	}

	for _, e := range out {
		if e.Path != "/pastes" || e.Key != "content" {
			t.Errorf("rule %d kept path %q key %q after scoping; a gateon "+
				"contribution that does not re-point is a profile entry that reads "+
				"as configured and does nothing", e.RuleID, e.Path, e.Key)
		}
	}
}

// TestGateonProfileRulesAreDeliberate guards the list itself.
//
// This is the file where "it produced a false positive" is a tempting reason to
// add a rule, and it is the wrong one: every rule produces a false positive on an
// application built to store attack text. The bar is whether the field is
// genuinely displayed rather than acted on, so the list stays short and each
// entry stays argued in a comment.
func TestGateonProfileRulesAreDeliberate(t *testing.T) {
	const max = 8
	for profile, ids := range gateonRules {
		if len(ids) > max {
			t.Errorf("%s contributes %d gateon rules, which is more than this "+
				"mechanism was meant to carry (%d). A long list means the bar has "+
				"moved from \"this field is displayed\" to \"this rule was noisy\".",
				profile, len(ids), max)
		}
		seen := map[types.RuleID]bool{}
		for _, id := range ids {
			if seen[id] {
				t.Errorf("%s names rule %d twice", profile, id)
			}
			seen[id] = true
		}
	}
}
