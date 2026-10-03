// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

func counterValueOf(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

// TestALoopbackWAFBlockIsShownAndHeldAgainstNobody is T27. Behind a local
// nginx or cloudflared with no trusted proxies every client arrives as
// 127.0.0.1, and RecordSecurityThreat dropped every threat from loopback: the
// WAF refused the attacks while Security Hub showed 0 threats and 0 WAF
// blocks. They are shown now -- and, as with any unattributed threat, kept
// out of reputation, which would otherwise refuse every local client at once.
func TestALoopbackWAFBlockIsShownAndHeldAgainstNobody(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	freshStore(t)
	const ip = "127.0.0.1"
	shared := repid.For(allowlistedBuild, ip)
	t.Cleanup(func() { ResetReputation(shared) })
	wafBlocks := MiddlewareWAFBlockedTotal.WithLabelValues("loopback-route", "942100")
	before := counterValueOf(t, wafBlocks)

	for range 3 {
		RecordSecurityThreat(SecurityThreat{
			Type: "waf_blocked", Category: "waf", Severity: "high", SourceIP: ip,
			RouteID: "loopback-route", TriggeredRules: `["942100"]`,
			Fingerprint: allowlistedBuild, Score: 100, ActionTaken: ActionBlocked,
		})
	}
	FlushThreats()

	if got := threatCountFrom(t, ip); got != 3 {
		t.Errorf("%d threats listed from loopback, want 3", got)
	}
	if got := counterValueOf(t, wafBlocks) - before; got != 3 {
		t.Errorf("WAF blocks counted: +%v, want +3", got)
	}
	if got := GetReputationScore(shared); got < 100 {
		t.Errorf("loopback's reputation fell to %v; a loopback threat must move no score", got)
	}
}
