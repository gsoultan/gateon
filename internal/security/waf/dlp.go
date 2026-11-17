// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"slices"

	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// The data-leak corpus has two consumers now. The engine compiles it and
// decides whether a response is refused; the middleware needs the same
// detectors to redact what they found, and needs to recognise a decision as
// having come from one of them.
//
// Both answers are derived from defaultSpecs rather than restated, because a
// second list of "which rules are DLP" is a list that goes stale the first time
// someone adds a detector and updates only one of them.

// DLPResponseRules returns the response-phase data-leak rules that load at the
// given paranoia level.
//
// The middleware uses these to find every leak in a body, not just the one the
// engine reported: the engine stops at the decision it is going to act on, which
// is the right thing for a block and the wrong thing for a redaction that has to
// cover the whole response.
func DLPResponseRules(paranoiaLevel int) rules.Set {
	if paranoiaLevel < 1 {
		paranoiaLevel = 1
	}
	set := make(rules.Set, 0, 32)
	for _, s := range defaultSpecs {
		if s.category == CategoryDLP && s.phase == types.PhaseResponseBody && s.pl <= paranoiaLevel {
			set = append(set, s.rule())
		}
	}
	return set
}

// IsCompromiseRule reports whether id is a response rule that recognises the
// result of a successful exploit rather than a value that should not have been
// on the page.
//
// The difference decides what redaction means. A card number cut out of a
// receipt leaves a receipt. Two lines cut out of an account file leave the
// rest of the account file, and the response still proves the request read a
// file it should not have.
func IsCompromiseRule(id types.RuleID) bool {
	_, ok := compromiseRuleIDs[id]
	return ok
}

// compromiseRuleIDs is the id set behind IsCompromiseRule.
var compromiseRuleIDs = func() map[types.RuleID]struct{} {
	ids := make(map[types.RuleID]struct{}, 8)
	for _, s := range defaultSpecs {
		if slices.Contains(s.tags, TagCompromise) {
			ids[types.RuleID(s.id)] = struct{}{}
		}
	}
	return ids
}()

// dlpRuleIDs is the id set behind IsDLPRule, built once from the corpus.
var dlpRuleIDs = func() map[types.RuleID]struct{} {
	ids := make(map[types.RuleID]struct{}, 32)
	for _, s := range defaultSpecs {
		if s.category == CategoryDLP {
			ids[types.RuleID(s.id)] = struct{}{}
		}
	}
	return ids
}()

// IsDLPRule reports whether a decision came from the data-leak corpus.
//
// This is what lets one action apply to data-leak findings and another to the
// rest: an operator who wants a card number redacted out of a response does not
// thereby want an SQL injection allowed through.
func IsDLPRule(id types.RuleID) bool {
	_, ok := dlpRuleIDs[id]
	return ok
}
