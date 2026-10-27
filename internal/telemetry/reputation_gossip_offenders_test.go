// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// ADR 0079 narrowed a score one address earned to that address, on the node
// that recorded it. The sync payload carried no addresses, so every peer read
// the same score as the whole network's: a client of an office NAT tripping a
// WAF rule twice behind one gateway refused every other client of its browser
// build on the network through every other gateway in the cluster. The payload
// now names the offenders; these tests pin that a peer applies the same rule,
// and that a payload naming none -- including one from a node that predates
// the field -- still refuses the network.

const (
	gossipOffender  = "203.0.113.10"
	gossipNeighbour = "203.0.113.77"
)

// sentReputation lowers the score of offendersBrowser on offender's network
// penalties times on this node and returns the identity and what it gossiped.
func sentReputation(t *testing.T, offender string, penalties int) (string, []byte) {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	d := &ReputationDelegate{}
	prev := gossipManager
	gossipManager = &GossipManager{delegate: d}
	t.Cleanup(func() { gossipManager = prev })

	id := repid.For(offendersBrowser, offender)
	for range penalties {
		DecreaseReputationOf(offendersBrowser, offender, 50, "test: waf_block")
	}
	sent := d.GetBroadcasts(2, 64*1024)
	if len(sent) != 1 {
		t.Fatalf("gossiped %d messages for one identity, want 1", len(sent))
	}
	forgetReputation(t, id)
	return id, sent[0]
}

// forgetReputation drops id from this node without broadcasting, so the node
// can play the peer that receives what it sent.
func forgetReputation(t *testing.T, id string) {
	t.Helper()
	dropReputation(id)
	t.Cleanup(func() { dropReputation(id) })
}

func dropReputation(id string) {
	shard := getRepShard(id)
	shard.mu.Lock()
	shard.cache.Remove(id)
	delete(shard.dirty, id)
	shard.mu.Unlock()
}

func receive(msg []byte) { (&ReputationDelegate{}).NotifyMsg(msg) }

func TestAPeerRefusesOnlyTheAddressThatEarnedAScore(t *testing.T) {
	id, msg := sentReputation(t, gossipOffender, 2)
	receive(msg)

	if got := ReputationScoreFor(id, gossipOffender); got >= 2 {
		t.Fatalf("on the peer the offender reads %.0f, want below the refusal bar", got)
	}
	if got := ReputationScoreFor(id, gossipNeighbour); got != neutralReputationScore {
		t.Fatalf("on the peer a neighbour of the offender reads %.0f, want %.0f: "+
			"the score one address earned refused its network once it was gossiped", got, neutralReputationScore)
	}
}

func TestAPayloadNamingNoOffenderRefusesTheNetwork(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	for name, offenders := range map[string]string{
		"a peer that predates the field":  ``,
		"an empty list":                   `,"offenders":[]`,
		"an entry that is no address":     `,"offenders":["not-an-address"]`,
		"more entries than a score keeps": `,"offenders":["203.0.113.10","203.0.113.11","203.0.113.12"]`,
	} {
		id := repid.For(offendersBrowser, gossipOffender)
		forgetReputation(t, id)
		receive(fmt.Appendf(nil, `{"fingerprint":%q,"score":0,"violation_count":2,"history":["waf_blocked"]%s}`, id, offenders))

		if got := ReputationScoreFor(id, gossipNeighbour); got >= 2 {
			t.Errorf("%s: a neighbour reads %.0f, want below the refusal bar: "+
				"a score that names nobody is everyone's on the network", name, got)
		}
		dropReputation(id)
	}
}

// Two gateways each catching a different address of one class on one network
// is a class attacking from two addresses, and the network's record, as it is
// when one gateway sees both. Their scores are equal, so neither peer takes
// the other's; the offenders have to merge anyway.
func TestOffendersSeenByDifferentPeersRefuseTheNetwork(t *testing.T) {
	_, fromOther := sentReputation(t, "203.0.113.11", 1)
	id := repid.For(offendersBrowser, gossipOffender)
	DecreaseReputationOf(offendersBrowser, gossipOffender, 50, "test: waf_block")
	receive(fromOther)

	if got := ReputationScoreFor(id, gossipNeighbour); got == neutralReputationScore {
		t.Fatalf("a neighbour reads the neutral %.0f after two gateways each caught a different "+
			"address, want the network's score, %.0f", got, GetReputationScore(id))
	}
}

// A release is a clean slate: an offender named before it must not count
// towards the second address that refuses the network.
func TestAReleaseFromAPeerForgetsTheOffenders(t *testing.T) {
	id, msg := sentReputation(t, gossipOffender, 1)
	receive(msg)
	receive(fmt.Appendf(nil, `{"fingerprint":%q,"score":100,"history":["Manual reset"]}`, id))
	DecreaseReputationOf(offendersBrowser, "203.0.113.11", 99, "test: waf_block")

	if got := ReputationScoreFor(id, gossipNeighbour); got != neutralReputationScore {
		t.Fatalf("a neighbour reads %.0f: an offender released through a peer still counted "+
			"towards refusing the network", got)
	}
}
