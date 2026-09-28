// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// Since ADR 0024 a reputation score is kept for a client class on a network,
// and the reputation blocker refuses every client of the class there once it
// falls. An allowlisted scanner's threats lowered that shared score, so the
// scanner's neighbours running the same build were refused for the scanner's
// traffic -- enforcement the allowlist exists to prevent, landing on clients it
// does not name. ADR 0031.

const allowlistedBuild = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"

// recordWAFBlockFrom records, through the store's own loop, what the WAF
// records when it refuses a payload from ip.
func recordWAFBlockFrom(ip string) {
	RecordSecurityThreat(SecurityThreat{
		Type: "waf_blocked", Category: "waf", Severity: "high", SourceIP: ip,
		Fingerprint: allowlistedBuild, JA4: "t13d1516h2_8daaf6152771_b0da82dd1658",
		Score: 100, Time: time.Now(), ActionTaken: ActionBlocked,
	})
	FlushThreats()
}

func TestAnAllowlistedSourceDoesNotLowerItsNetworksScore(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	freshStore(t)
	const scanner, stranger = "203.0.113.50", "198.51.100.50"
	shared := repid.For(allowlistedBuild, scanner)
	t.Cleanup(func() {
		ResetReputation(shared)
		ResetReputation(repid.For(allowlistedBuild, stranger))
	})
	mitigation.SetAllowlist(mitigation.ParseAllowlist(scanner + "/32"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	recordWAFBlockFrom(scanner)
	if got := GetReputationScore(shared); got < 100 {
		t.Errorf("an allowlisted scanner's WAF block lowered the score its build holds on its "+
			"network to %v; the reputation blocker refuses every client of the build there on that "+
			"score, so the scanner's neighbours pay for traffic the operator allowlisted", got)
	}
	if n := threatCountFrom(t, scanner); n != 1 {
		t.Errorf("%d of the allowlisted scanner's 1 threat is recorded; the allowlist exempts the "+
			"score, never the record", n)
	}

	// The control: the same threat from an address the allowlist does not name
	// still lowers its network's score, so the assertion above is not vacuous.
	recordWAFBlockFrom(stranger)
	if got := GetReputationScore(repid.For(allowlistedBuild, stranger)); got >= 100 {
		t.Errorf("a WAF block from an address that is not allowlisted left its score at %v", got)
	}
}

// The incident responder penalises every address that took part in an
// incident; the rule is DecreaseReputationOf's, so it holds there too.
func TestDecreaseReputationOfSkipsAnAllowlistedSource(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	const allowlisted, other = "203.0.113.51", "203.0.113.52"
	mitigation.SetAllowlist(mitigation.ParseAllowlist(allowlisted + "/32"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	id := repid.For(allowlistedBuild, allowlisted) // the same /24 as other: one shared score
	t.Cleanup(func() { ResetReputation(id) })

	DecreaseReputationOf(allowlistedBuild, allowlisted, 50, "test: correlated incident")
	if got := GetReputationScore(id); got < 100 {
		t.Errorf("a penalty for an allowlisted participant lowered its network's score to %v", got)
	}
	DecreaseReputationOf(allowlistedBuild, other, 50, "test: correlated incident")
	if got := GetReputationScore(id); got >= 100 {
		t.Errorf("a penalty for a participant the allowlist does not name did not move the score (%v)", got)
	}
}

// threatCountFrom counts the stored threats from ip.
func threatCountFrom(t *testing.T, ip string) int {
	t.Helper()
	n := 0
	for _, th := range GetSecurityThreatsLite(t.Context(), 1000, 0, nil) {
		if th.SourceIP == ip {
			n++
		}
	}
	return n
}
