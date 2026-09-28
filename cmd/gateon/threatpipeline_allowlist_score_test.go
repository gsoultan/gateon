// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/gsoultan/gateon/internal/security/correlation"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// The responder penalises the class of every address that took part in an
// incident. A score is shared by the class on its network and enforced
// against all of it (ADR 0024), so a penalty for an allowlisted participant
// refused its neighbours who run the same build. ADR 0031.
func TestTheResponderDoesNotPenaliseAnAllowlistedParticipant(t *testing.T) {
	const build = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"
	const attacker, allowlisted, other = "198.51.100.9", "203.0.113.9", "192.0.2.9"
	t.Setenv(envMitigationAllowlist, allowlisted+"/32")
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	publishMitigationAllowlist()
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
	for _, ip := range []string{attacker, allowlisted, other} {
		id := repid.For(build, ip)
		t.Cleanup(func() { telemetry.ResetReputation(id) })
	}

	initMitigator(nil).Handle(correlation.Incident{
		SourceIP: attacker, SourceIPs: []string{allowlisted, other}, Fingerprint: build,
		Severity: "high", SignalTypes: []string{"waf_blocked", "honeypot_triggered"},
	})

	if got := telemetry.GetReputationScore(repid.For(build, allowlisted)); got < 100 {
		t.Errorf("an allowlisted participant's network now scores %v for its build: its neighbours "+
			"running the build are refused for an incident the operator exempted it from", got)
	}
	if got := telemetry.GetReputationScore(repid.For(build, other)); got >= 100 {
		t.Errorf("a participant the allowlist does not name was not penalised (%v); the assertion "+
			"above proves nothing", got)
	}
}
