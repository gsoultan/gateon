// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
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
