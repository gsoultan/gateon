// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// The reputation blocker refuses a score under 2 on every route. That score
// was kept for one browser build on one /24, so two WAF blocks from two people
// on one office or carrier network -- one of them the corpus's own recorded
// false positive, a password with metacharacters -- took the score to 0 and
// every other person on that /24 with the same browser got a 403 everywhere,
// for hours. Root cause: a penalty for what one address did was recorded, and
// enforced, under a key every address on its /24 shared (ADR 0011, 0024).

func TestTwoBlocksOnANetworkDoNotRefuseItsOtherClients(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "per-address.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	const first, second, bystander = "198.18.7.10", "198.18.7.11", "198.18.7.12"
	req := func(ip string) *http.Request {
		return enteredRequest(ip, http.MethodGet, "t13d1516h2_8daaf6152771_b0da82dd1658", browserHeaders)
	}
	for _, ip := range []string{first, second} {
		r := req(ip)
		telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
			Type: "waf_blocked", Category: "waf", Severity: "high", SourceIP: ip,
			Fingerprint: telemetry.GetIPFingerprint(r), Score: 100,
			Time: time.Now(), ActionTaken: telemetry.ActionBlocked,
		})
	}
	telemetry.FlushThreats()
	t.Cleanup(func() {
		for _, ip := range []string{first, second, bystander} {
			telemetry.ResetReputation(telemetry.GetReputationID(req(ip)))
		}
	})

	if got := telemetry.GetReputationScore(telemetry.GetReputationID(req(bystander))); got < 100 {
		t.Errorf("a client on the same /24 with the same browser, which did nothing, has score %v; "+
			"the blocker refuses under 2 on every route", got)
	}
	// The control: the address that was blocked is still the one penalised.
	if got := telemetry.GetReputationScore(telemetry.GetReputationID(req(first))); got >= 100 {
		t.Errorf("the address the WAF blocked kept score %v; the penalty went nowhere", got)
	}
}
