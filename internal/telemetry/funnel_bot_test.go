// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import "testing"

// TestTheFunnelCountsTheBotOutcomesThatAreRecorded: the bot stage summed
// "blocked", "integrity_failed" and "challenge_failed". Bot management records
// none of the last two; it records a challenge it served in place of the
// response ("challenge_served", and "pow_challenge_served" for proof of
// work) -- a 403 the backend never saw -- and the threat pipeline records its
// blocks as "blocked". A solved challenge is a request let through.
func TestTheFunnelCountsTheBotOutcomesThatAreRecorded(t *testing.T) {
	before := buildMitigationFunnel(gatherIndex(t)).BotBlocked
	for _, outcome := range []string{"challenge_served", "pow_challenge_served", ActionBlocked, "challenge_solved", "pow_challenge_solved"} {
		MiddlewareBotManagementTotal.WithLabelValues("funnel-bot", outcome).Inc()
	}
	if got := buildMitigationFunnel(gatherIndex(t)).BotBlocked - before; got != 3 {
		t.Fatalf("bot stage +%v, want +3 (two challenges served, one block; solved ones passed)", got)
	}
}
