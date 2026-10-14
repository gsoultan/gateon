// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"strconv"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// A reputation score is what the reputation blocker refuses on, on every
// route, for every client of one build on one network (ADR 0011, 0024). So a
// threat that moves it is a gateway-wide refusal of that whole population, and
// a refusal of who a client is or how much it sends is not one: the route that
// refused it has already given its answer.
//
// On the built gateway, eight 429s from one address on a rate-limited route got
// that address and its neighbour on the same /24 a 403 on an unrelated route.
// The limiter fed itself as well: it scales a client's limit by its
// reputation, so each rejection tightened the limit that produced the next.
// Root cause: processThreat lowered the score for every threat held against
// its source, and a rate limit, a geofence and a bot-policy block all are.

// volumeAndPolicyRefusals are refusals a client earns for who it is or how much it
// sends, recorded as their middlewares record them.
var volumeAndPolicyRefusals = []SecurityThreat{
	{Type: "rate_limit", Category: "abuse", Severity: "medium", Score: 10},
	{Type: "geoip_block", Category: "geofencing", Severity: "medium", Score: 50},
	{Type: "bot_detected", Category: "bot", Severity: "medium", Score: 60},
}

func TestARefusalOfPolicyNotConductMovesNoReputation(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	freshStore(t)

	for i, refusal := range volumeAndPolicyRefusals {
		// Its own /24 per case, so one case cannot lower the next one's score.
		network := "203.0." + strconv.Itoa(120+i) + "."
		busy, neighbour := network+"10", network+"11"
		t.Cleanup(func() { ResetReputation(repid.For(allowlistedBuild, busy)) })

		for range 30 {
			th := refusal
			th.SourceIP, th.Fingerprint = busy, allowlistedBuild
			th.Time, th.ActionTaken, th.Mitigated = time.Now(), ActionBlocked, true
			RecordSecurityThreat(th)
		}
		FlushThreats()

		if got := GetReputationScore(repid.For(allowlistedBuild, neighbour)); got < 100 {
			t.Errorf("%s: thirty refusals of %s lowered the score its neighbour %s is refused on "+
				"to %v; a %s is policy about who a client is or how much it sends, not evidence "+
				"of an attack", refusal.Type, busy, neighbour, got, refusal.Type)
		}
	}

	// The control: an attack the WAF refused still lowers the score, so the
	// assertions above are not passing on a pipeline that moves nothing.
	const attacker = "203.0.119.10"
	t.Cleanup(func() { ResetReputation(repid.For(allowlistedBuild, attacker)) })
	recordWAFBlockFrom(attacker)
	if got := GetReputationScore(repid.For(allowlistedBuild, attacker)); got >= 100 {
		t.Errorf("a WAF block left its source's score at %v; the control is not moving it", got)
	}
}
