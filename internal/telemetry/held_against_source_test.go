// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// TestARefusalOfALowScoreDoesNotLowerItFurther: the reputation blocker's
// refusal is recorded with a score of 100 minus the reputation, and every
// recorded threat took half its score off the client's. So each refused retry
// pushed the score of everyone on the network with that build back to zero,
// and a client refused by mistake stayed refused for as long as it kept trying.
// A refusal of an earlier decision is that decision coming back, not new
// evidence (ADR 0055).
func TestARefusalOfALowScoreDoesNotLowerItFurther(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	freshStore(t)
	const client = "203.0.113.60"
	id := repid.For(allowlistedBuild, client)
	t.Cleanup(func() { ResetReputation(id) })
	DecreaseReputation(id, 98.5, "test: an earlier penalty")
	before := GetReputationScore(id)

	for range 3 {
		RecordSecurityThreat(SecurityThreat{
			Type: "reputation_block", Category: "bot", Severity: "high", SourceIP: client,
			Fingerprint: allowlistedBuild, Score: 100 - before, Time: time.Now(), ActionTaken: ActionBlocked,
		})
		FlushThreats()
	}

	if got := GetReputationScore(id); got != before {
		t.Errorf("three reputation refusals moved the score from %v to %v", before, got)
	}
	if n := threatCountFrom(t, client); n != 3 {
		t.Errorf("%d of 3 refusals are recorded; they are held against nobody, never hidden", n)
	}
}

// TestHeldAgainstSource pins which threats may count against their source.
func TestHeldAgainstSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		th   SecurityThreat
		want bool
	}{
		{"a WAF refusal", SecurityThreat{Type: "waf_blocked"}, true},
		{"a trap sprung", SecurityThreat{Type: "honeypot_triggered"}, true},
		{"an audit-only match", SecurityThreat{Type: "waf_detected", Observed: true}, false},
		{"a cross-site trap load", SecurityThreat{Type: "honeypot_triggered", Unattributed: true}, false},
		{"a feed or shun refusal", SecurityThreat{Type: "ip_mitigation"}, false},
		{"a fingerprint block refusal", SecurityThreat{Type: "user_mitigation"}, false},
		{"a kernel shun", SecurityThreat{Type: "ip_shunning"}, false},
		{"a reputation refusal", SecurityThreat{Type: "reputation_block"}, false},
		// A stored row reads the same: the type says it (review 3, F1).
		{"the WAF's reputation rules refusing", SecurityThreat{
			Type: ThreatWAFReputationBlock, Category: "Reputation", ActionTaken: "blocked", Mitigated: true,
		}, false},
	} {
		if got := tc.th.HeldAgainstSource(); got != tc.want {
			t.Errorf("%s: HeldAgainstSource() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
