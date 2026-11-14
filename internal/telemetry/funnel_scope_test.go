// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import "testing"

// TestTheFunnelLeavesOutTheManagementPlane: a failed dashboard sign-in is
// counted under route "gateon-management", and the funnel's Auth Failures
// stage summed every route. A gateway with no proxied request refused showed
// "Auth Failures 1" under an ingress of nothing refused, and its stages added
// up to more than its refusals.
func TestTheFunnelLeavesOutTheManagementPlane(t *testing.T) {
	before := buildMitigationFunnel(gatherIndex(t))
	MiddlewareAuthFailuresTotal.WithLabelValues(ManagementRoute, "paseto").Inc()
	MiddlewareAuthFailuresTotal.WithLabelValues("funnel-scope-route", "jwt").Inc()
	after := buildMitigationFunnel(gatherIndex(t))
	if got := after.AuthFailures - before.AuthFailures; got != 1 {
		t.Fatalf("auth stage +%v, want +1: only the proxied route's failure", got)
	}
}

// TestAReputationBlockIsABlockedSource: a reputation block is filed under
// category "bot", and the funnel's bot rule claimed it, so a gateway with no
// bot management configured reported every client refused for its reputation
// under "Bot Mitigation". It is a refusal of the source, beside the shun and the
// client-build block.
func TestAReputationBlockIsABlockedSource(t *testing.T) {
	before := buildMitigationFunnel(gatherIndex(t))
	recordMitigationFunnel(&SecurityThreat{
		Type: typeReputationBlock, Category: "bot", RouteID: "funnel-rep-route", ActionTaken: ActionBlocked,
	})
	after := buildMitigationFunnel(gatherIndex(t))
	if got := after.BotBlocked - before.BotBlocked; got != 0 {
		t.Errorf("bot stage +%v for a reputation block, want +0", got)
	}
	if got := after.MitigationBlocked - before.MitigationBlocked; got != 1 {
		t.Errorf("blocked-source stage +%v for a reputation block, want +1", got)
	}
}
