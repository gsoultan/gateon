// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"testing"

	"github.com/gsoultan/gwaf/types"
)

// matchedAtPhase reports the rules at or below paranoia level pl whose operator
// matches payload at the given phase. gwaf documents PhaseRequestHeaders as
// never reading the body, so a payload matched only at that phase gets a free
// pass when it arrives in a form or JSON body.
func matchedAtPhase(payload string, phase types.Phase, pl int) []uint32 {
	var out []uint32
	for _, s := range defaultSpecs {
		if s.phase != phase || s.pl > pl {
			continue
		}
		if _, ok := s.op.Eval(nil, []byte(payload)); ok {
			out = append(out, s.id)
		}
	}
	return out
}

const shellshock = `() { :; }; /bin/cat /etc/passwd`

// TestShellshockIsCaughtInABodyAtPL2 pins the gap gwaf's own diagnostics
// reported: rule 1100014 declares TargetArgs but runs at the header phase, so
// it sees the query string and not a body. A CGI host behind the gateway was
// exploitable by POST while Shellshock read as covered.
func TestShellshockIsCaughtInABodyAtPL2(t *testing.T) {
	t.Parallel()

	if got := matchedAtPhase(shellshock, types.PhaseRequestBody, 2); len(got) == 0 {
		t.Errorf("no request-body rule matches a Shellshock payload at PL2; "+
			"only the header phase catches it (%v), which never reads a body",
			matchedAtPhase(shellshock, types.PhaseRequestHeaders, 2))
	}
}

// TestShellshockBodyRuleIsNotInThePL1Budget records the price of the fix rather
// than hiding it. The pattern is all metacharacters, so rx can extract no
// literal to prefilter on and the rule runs on every body in its phase. PL1
// budgets four such rules and already spends them (see
// TestUnconditionalRulesAreBudgeted), so the body half lives at PL2. If someone
// later earns a literal for it, moving it to PL1 is the reward -- but then this
// test should fail and be deleted deliberately, not quietly.
func TestShellshockBodyRuleIsNotInThePL1Budget(t *testing.T) {
	t.Parallel()

	if got := matchedAtPhase(shellshock, types.PhaseRequestBody, 1); len(got) != 0 {
		t.Errorf("rules %v put an unconditional Shellshock regex on every PL1 "+
			"body; check it against the PL1 unconditional ceiling first", got)
	}
	// The query-string form must still be covered at PL1, or the tiering has
	// quietly dropped coverage instead of moving it.
	if got := matchedAtPhase(shellshock, types.PhaseRequestHeaders, 1); len(got) == 0 {
		t.Error("PL1 no longer catches Shellshock in a query string")
	}
}

// TestNullByteStaysOutOfTheBodyPhase is the inverse, and is deliberate. A
// body-phase null-byte rule matches every binary upload -- a PNG is full of
// them -- so adding the twin that gwaf's diagnostic suggests would turn image
// uploads into 403s. The narrow rule is the correct one; this test stops
// someone "fixing" the diagnostic by breaking uploads.
func TestNullByteStaysOutOfTheBodyPhase(t *testing.T) {
	t.Parallel()

	// A PNG signature carries NULs in its first eight bytes.
	const png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

	if got := matchedAtPhase(png, types.PhaseRequestBody, 4); len(got) != 0 {
		t.Errorf("request-body rules %v match a PNG header; a null-byte or CRLF "+
			"rule at the body phase blocks every binary upload", got)
	}
}
