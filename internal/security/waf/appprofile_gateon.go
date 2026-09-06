// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"github.com/gsoultan/gwaf/rules"
	"github.com/gsoultan/gwaf/types"
)

// An app profile is a statement about an application, not about a ruleset: this
// field is stored and displayed, never executed or queried. gwaf answers it for
// the rules gwaf ships, and cannot answer it for the rules gateon adds on top —
// it has never heard of them.
//
// So a paste service selecting `issue_tracker` had gwaf's exceptions applied and
// gateon's own rules still refusing the same content. Measured on the benign
// corpus at paranoia 2: a pasted nginx config and a `.env.example` blocked on
// 1150003, a GitHub Actions workflow and a markdown README blocked on 1151008 —
// all four already scoped to the operator's paste routes, and all four refused by
// rules no profile had ever been able to name.
//
// The premise is the same one gwaf states and the same one that makes the whole
// mechanism safe: these are exceptions scoped to named paths and fields, never a
// weaker ruleset. `TestGateonProfileRulesAreScopedNotAGlobalOff` pins that the
// same payload elsewhere still blocks.

// gateonProfileRules names the gateon-authored rules each profile must also
// exempt, alongside the ones gwaf contributes.
//
// Adding an entry is a security decision and should read like one. The test for
// each is not "does this rule produce a false positive here" — every rule does,
// on an application built to store attack text — but "is this field genuinely
// displayed rather than acted on". A rule whose finding would still be dangerous
// in stored content does not belong here at any paranoia level.
var gateonProfileRules = map[AppProfile][]types.RuleID{
	AppProfileIssueTracker: {
		// 1150003, "SSRF attempt against an internal target": matches
		// 127.0.0.1, localhost and the cloud metadata hosts in an argument.
		//
		// An SSRF finding is about a URL the *server* will fetch. A paste service
		// stores the string and renders it; nothing dials it. Configuration is
		// the single most pasted category of text there is, and an nginx
		// `proxy_pass http://127.0.0.1:8080` or a `.env.example` carrying
		// `postgres://user:pass@localhost:5432` is the ordinary shape of it.
		1150003,

		// 1151008, "Advanced shell injection attempt": a shell metacharacter
		// followed by a binary name — `&& make test`, a backticked command in a
		// README, `; python`.
		//
		// Same reasoning as gwaf's IDShelliSemantic, which this profile already
		// exempts: the finding is about a string reaching a shell. In a field
		// that is displayed it reaches a renderer. A CI workflow and a fenced
		// code block are what these applications exist to hold.
		1151008,
	},
}

// GateonProfileExceptions returns gateon's own contribution to a profile.
//
// The shape deliberately mirrors gwaf's: the same default path and field names,
// so that an install which configures no scope behaves consistently across both
// halves, and one which does gets both re-pointed by ScopeAppProfileExceptions.
// A keyed exception is what that function re-scopes, so these carry keys.
func GateonProfileExceptions(p AppProfile) []rules.Exception {
	ids := gateonProfileRules[p]
	if len(ids) == 0 {
		return nil
	}
	const note = "this application stores attack payloads as content by design; " +
		"the field is displayed, never executed or queried (gateon rule)"

	out := make([]rules.Exception, 0, len(ids)*2)
	for _, id := range ids {
		for _, k := range []string{"description", "body"} {
			out = append(out, rules.Exception{
				RuleID: id, Path: "/rest/api/*", Target: types.TargetArgs, Key: k, Note: note,
			})
		}
	}
	return out
}
