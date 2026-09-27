// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func freshAttackGraph(t *testing.T) time.Time {
	t.Helper()
	ResetAttackGraph()
	t.Cleanup(ResetAttackGraph)
	return time.Unix(1_700_000_000, 0)
}

// TestAttackGraphIsBounded: the old graph's ceiling was sixteen shards of 5000
// nodes with 1000 neighbours each. An attacker rotating client classes and
// addresses must not grow this one past its caps, and the classes it keeps
// are the ones renewed most recently.
func TestAttackGraphIsBounded(t *testing.T) {
	at := freshAttackGraph(t)
	for c := range 2 * maxAttackClasses {
		for a := range 2 * maxAttackLinksPerClass {
			ObserveAttackLink(fmt.Sprintf("class-%d", c), fmt.Sprintf("10.%d.%d.%d", c/250, c%250, a%250+1), 5,
				at.Add(time.Duration(c)*time.Second+time.Duration(a)*time.Millisecond))
		}
	}
	classes, links := attackGraphSize()
	if classes > maxAttackClasses || links > maxAttackClasses*maxAttackLinksPerClass {
		t.Fatalf("the store holds %d classes and %d links; the caps are %d and %d per class",
			classes, links, maxAttackClasses, maxAttackLinksPerClass)
	}
	newest := fmt.Sprintf("class-%d", 2*maxAttackClasses-1)
	if !slices.ContainsFunc(AttackClusters(at.Add(time.Hour/4), 1, 1), func(c AttackCluster) bool { return c.Fingerprint == newest }) {
		t.Errorf("the most recently renewed class was evicted")
	}
}

// TestAttackLinksFadeAndExpire: the old graph never decayed, so five visitors
// days apart made the same cluster as five at once.
func TestAttackLinksFadeAndExpire(t *testing.T) {
	at := freshAttackGraph(t)
	ObserveAttackLink("class-a", "10.0.0.1", 6, at)

	if got := AttackClusters(at, 1, 3); len(got) != 1 {
		t.Fatalf("a fresh link with evidence 6 does not reach a bar of 3: %v", got)
	}
	if got := AttackClusters(at.Add(attackLinkHalfLife+time.Minute), 1, 3); len(got) != 0 {
		t.Errorf("evidence 6 still reaches 3 more than a half-life later: %v", got)
	}
	AttackClusters(at.Add(attackLinkWindow+time.Second), 1, 0)
	if classes, links := attackGraphSize(); classes != 0 || links != 0 {
		t.Errorf("a link unrenewed for %v is still held (%d classes, %d links)", attackLinkWindow, classes, links)
	}
}

// TestRenewingALinkDoesNotCountItTwice: each analysis pass re-reads the same
// threats, so the same evidence arrives again and again.
func TestRenewingALinkDoesNotCountItTwice(t *testing.T) {
	at := freshAttackGraph(t)
	for pass := range 5 {
		ObserveAttackLink("class-a", "10.0.0.1", 2, at.Add(time.Duration(pass)*time.Second))
	}
	if got := AttackClusters(at.Add(5*time.Second), 1, 2.5); len(got) != 0 {
		t.Errorf("evidence 2 observed five times reads as %.1f", got[0].Evidence[0])
	}
}

// TestAttackClustersCopyOnlyWhatQualifies: the detector used to deep-copy the
// whole graph every pass to look at a few hubs.
func TestAttackClustersCopyOnlyWhatQualifies(t *testing.T) {
	at := freshAttackGraph(t)
	for c := range maxAttackClasses {
		for a := range 4 {
			ObserveAttackLink(fmt.Sprintf("class-%d", c), fmt.Sprintf("10.1.%d.%d", c, a+1), 5, at)
		}
	}
	if allocs := testing.AllocsPerRun(20, func() { AttackClusters(at, 5, 3) }); allocs != 0 {
		t.Errorf("a pass with no qualifying class allocated %.0f times over %d links", allocs, 4*maxAttackClasses)
	}
}

// TestGossipedAttackLinksAreFiled: distributed mode never worked -- peers sent
// ip -> fp edges and the detector read fp -> ip. A peer's attack link is now
// filed like a local one; the evidence-free edges older peers still send are not.
func TestGossipedAttackLinksAreFiled(t *testing.T) {
	freshAttackGraph(t)
	delegate := &ReputationDelegate{}
	send := func(ip, typ string, weight float64) {
		msg, err := json.Marshal(&gateonv1.GraphEdgeSyncPayload{SourceNode: ip, TargetNode: "fp:class-g", Weight: weight, Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		delegate.NotifyMsg(msg)
	}
	for v := range 5 {
		send(fmt.Sprintf("10.2.0.%d", v+1), "fp_ip", 2)
	}
	if got := AttackClusters(time.Now(), 1, 0); len(got) != 0 {
		t.Fatalf("evidence-free edges from an older peer were filed: %v", got)
	}
	for v := range 5 {
		send(fmt.Sprintf("10.2.0.%d", v+1), attackLinkEdgeType, 1e9)
	}
	got := AttackClusters(time.Now(), 5, 3)
	if len(got) != 1 || len(got[0].Addresses) != 5 {
		t.Fatalf("five peers' attack links behind one class: clusters %v", got)
	}
	if got[0].Evidence[0] > maxRemoteAttackEvidence {
		t.Errorf("a peer's claim of 1e9 was filed as %.0f", got[0].Evidence[0])
	}
}
