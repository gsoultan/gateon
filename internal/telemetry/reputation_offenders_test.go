// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// A reputation score is kept for a browser class on a /24 (repid.For), and a
// WAF block costs 50, so two blocks took the score to zero and the reputation
// blocker refused the whole class on the whole network. On an office NAT, a
// campus or a CGNAT pool that is every client of one browser build, refused
// for hours because one of them tripped a WAF rule twice. These tests pin the
// rule ADR 0079 puts in its place: the score is still the network's, but a
// score one address alone earned refuses that address and nobody else, and a
// second offending address makes it the network's to answer for, as before.

const offendersBrowser = "t13d1516h2_8daaf6152771_b0da82dd1658"

func recordedScore(t *testing.T, sourceIP string, penalties int) string {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	id := repid.For(offendersBrowser, sourceIP)
	t.Cleanup(func() { ResetReputation(id) })
	for range penalties {
		DecreaseReputationOf(offendersBrowser, sourceIP, 50, "test: waf_block")
	}
	return id
}

func TestAScoreOneAddressEarnedRefusesOnlyThatAddress(t *testing.T) {
	const offender, neighbour = "203.0.113.10", "203.0.113.77"
	id := recordedScore(t, offender, 2)

	if got := ReputationScoreFor(id, offender); got >= 2 {
		t.Fatalf("the offender reads %.0f, want below the refusal bar: the client that earned the score is still refused", got)
	}
	if got := ReputationFor(id, offender); got >= 2 {
		t.Fatalf("the offender reads %.0f through the recovering read, want below the refusal bar", got)
	}
	if got := ReputationScoreFor(id, neighbour); got != neutralReputationScore {
		t.Fatalf("a neighbour on the offender's /24 reads %.0f, want %.0f: it sent none of the threats", got, neutralReputationScore)
	}
	if got := ReputationFor(id, neighbour); got != neutralReputationScore {
		t.Fatalf("a neighbour reads %.0f through the recovering read, want %.0f", got, neutralReputationScore)
	}
	if got := GetReputationScore(id); got >= 2 {
		t.Fatalf("the identity's own score reads %.0f; the dashboard and the metrics still see the network's record", got)
	}
}

func TestAScoreTwoAddressesEarnedRefusesTheNetwork(t *testing.T) {
	const first, second, neighbour = "203.0.113.10", "203.0.113.11", "203.0.113.77"
	id := recordedScore(t, first, 1)
	DecreaseReputationOf(offendersBrowser, second, 50, "test: waf_block")

	if got := ReputationScoreFor(id, neighbour); got >= 2 {
		t.Fatalf("a neighbour reads %.0f once two addresses lowered the score, want below the refusal bar: "+
			"a class attacking from more than one address is the network's record, as it always was", got)
	}
}

// A score with no address to name -- a peer's, or one lowered through
// DecreaseReputation -- is read as everyone's on the network, as every score
// was before. Narrowing it would let a score lose its reach by travelling.
func TestAScoreWithNoOffenderNamedRefusesTheNetwork(t *testing.T) {
	const neighbour = "203.0.113.77"
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")

	local := repid.For(offendersBrowser, "203.0.113.10")
	t.Cleanup(func() { ResetReputation(local) })
	DecreaseReputation(local, 99, "test: unnamed")
	if got := ReputationScoreFor(local, neighbour); got >= 2 {
		t.Fatalf("a neighbour reads %.0f against a score lowered with no address, want below the refusal bar", got)
	}

	remote := repid.For(offendersBrowser, "198.51.100.10")
	t.Cleanup(func() { ResetReputation(remote) })
	ApplyRemoteReputation(remote, 0, 3, nil)
	if got := ReputationScoreFor(remote, "198.51.100.77"); got >= 2 {
		t.Fatalf("a neighbour reads %.0f against a peer's score, want below the refusal bar", got)
	}
}

// The violation count raises every later penalty and slows recovery, and it
// reset only once LastEvent was a day old. Recovery moves LastEvent, and it
// runs on every request after an hour's quiet, so an identity with traffic
// every hour -- any shared network -- never reset: a day after its last
// violation it still paid for it, and a week after, more.
func TestViolationCountDecaysOnANetworkThatNeverGoesQuiet(t *testing.T) {
	const fp = "rep-busy-network-decay"
	now := time.Now()
	seedReputation(t, fp, &Reputation{
		Score:          60,
		ViolationCount: 3,
		RecoveryRate:   1.0 / (1.0 + 3.0/5.0),
		LastViolation:  now.Add(-30 * time.Hour),
		LastEvent:      now.Add(-90 * time.Minute), // the last recovery, on the last hour's traffic
		Offenders:      []string{"203.0.113.10"},
	})

	GetReputation(fp)

	shard := getRepShard(fp)
	shard.mu.RLock()
	val, ok := shard.cache.Peek(fp)
	shard.mu.RUnlock()
	if !ok {
		t.Fatal("entry vanished")
	}
	r := val.(*Reputation)
	if r.ViolationCount != 0 {
		t.Fatalf("ViolationCount = %d a day and more after the last violation, want 0", r.ViolationCount)
	}
	if r.RecoveryRate != 1.0 {
		t.Fatalf("RecoveryRate = %.2f after the count reset, want the base 1.0", r.RecoveryRate)
	}
	if len(r.Offenders) != 0 {
		t.Fatalf("Offenders = %v after the count reset, want none: the record that named them has lapsed", r.Offenders)
	}
}
