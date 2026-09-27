// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// "Graph Intelligence" reported any five addresses sharing a JA4+ value as a
// coordinated botnet, at a score the diagnostics loop throttled in the kernel;
// it never forgot a link; and its distributed mode could not see what peers
// sent. JA4+ identifies a browser class, not a client (mem:reputation_identity).
// Found by the 2026-09-27 AI-analysis review as open findings; fixed with them.

// TestGraphIntelligenceDoesNotCallABrowserClassABotnet: five people load the
// same three pages with the same stock browser; each was once turned away by
// the rate limiter, which is not an attack. Nothing about them is shared but
// the browser -- neither Graph Intelligence nor the per-address detector's
// fingerprint check may call them one actor, on any number of passes.
func TestGraphIntelligenceDoesNotCallABrowserClassABotnet(t *testing.T) {
	freshGraph(t)
	class := "t13d1516h2_8daaf6152771_" + t.Name()
	now := time.Now()
	tf := newTraffic(31, now.Add(-time.Minute))
	for v := range 5 {
		ip := fmt.Sprintf("10.40.0.%d", v+1)
		tf.classVisitor(ip, class, now.Add(-time.Minute+time.Duration(v*3)*time.Second))
		tf.threats = append(tf.threats, &telemetry.SecurityThreat{
			SourceIP: ip, Fingerprint: class, Type: "rate_limit", Category: "abuse", Mitigated: true, Time: now,
		})
	}
	for pass := range 3 {
		data := tf.data()
		data.Now = now.Add(time.Duration(pass) * time.Minute)
		for _, a := range graphEngine().Analyze(t.Context(), data) {
			if a.GetType() == graphCoordinatedType || strings.Contains(a.GetDescription(), "Multi-IP attack") {
				t.Errorf("pass %d: %s (score %.0f): %q", pass, a.GetType(), a.GetScore(), a.GetDescription())
			}
		}
	}
	// Not merely unreported: not linked. A gossiping peer has no traces of
	// these addresses to weigh, so a link is all it would see.
	for _, c := range telemetry.AttackClusters(now.Add(2*time.Minute), 1, 0) {
		if c.Fingerprint == class {
			t.Errorf("addresses with no attack evidence were linked to their browser class: %v", c.Addresses)
		}
	}
}

// TestGraphIntelligenceReportsACampaign: five addresses running one tool, each
// blocked by the WAF three times within a minute. This is what the detector is
// for, and it still says so.
func TestGraphIntelligenceReportsACampaign(t *testing.T) {
	freshGraph(t)
	class := "t13d0000h1_000000000000_" + t.Name()
	now := time.Now()
	tf := newTraffic(32, now.Add(-10*time.Minute))
	var attackers []string
	for v := range 5 {
		ip := fmt.Sprintf("10.41.0.%d", v+1)
		attackers = append(attackers, ip)
		tf.classAttacker(ip, class, 3, now.Add(-time.Minute))
	}
	data := tf.data()
	data.Now = now
	f := graphFinding(t, graphEngine().Analyze(t.Context(), data), class)
	if f == nil {
		t.Fatalf("five addresses with one tool, each blocked three times by the WAF, were not reported")
	}
	if !slices.Equal(f.GetSourceIps(), attackers) {
		t.Errorf("the finding names %v, want %v", f.GetSourceIps(), attackers)
	}
}

// TestGraphIntelligenceNeedsEvidenceFromEveryAddress: four addresses with an
// attacker's record and six with one WAF block each -- the kind a browser earns
// from a single false positive -- are not a campaign of ten, or of five.
func TestGraphIntelligenceNeedsEvidenceFromEveryAddress(t *testing.T) {
	freshGraph(t)
	class := "t13d0000h1_111111111111_" + t.Name()
	now := time.Now()
	tf := newTraffic(33, now.Add(-10*time.Minute))
	for v := range 10 {
		blocks := 1
		if v < 4 {
			blocks = 3
		}
		tf.classAttacker(fmt.Sprintf("10.42.0.%d", v+1), class, blocks, now.Add(-time.Minute))
	}
	data := tf.data()
	data.Now = now
	if f := graphFinding(t, graphEngine().Analyze(t.Context(), data), class); f != nil {
		t.Errorf("reported: %q", f.GetDescription())
	}
}

// TestGraphIntelligenceIgnoresAFewBadUsersOfACommonBrowser: twenty addresses
// present one browser class, and five of them were each blocked three times --
// a form that trips the WAF for anyone who submits it looks exactly like this.
// Five of twenty is a browser with some unlucky users, not a tool.
func TestGraphIntelligenceIgnoresAFewBadUsersOfACommonBrowser(t *testing.T) {
	freshGraph(t)
	class := "t13d1516h2_8daaf6152771_" + t.Name()
	now := time.Now()
	tf := newTraffic(34, now.Add(-10*time.Minute))
	for v := range 20 {
		ip := fmt.Sprintf("10.43.0.%d", v+1)
		tf.classVisitor(ip, class, now.Add(-2*time.Minute))
		if v < 5 {
			tf.classAttacker(ip, class, 3, now.Add(-time.Minute))
		}
	}
	data := tf.data()
	data.Now = now
	if f := graphFinding(t, graphEngine().Analyze(t.Context(), data), class); f != nil {
		t.Errorf("reported: %q", f.GetDescription())
	}
}

// TestGraphIntelligenceSparesAnOfficeWithOneAttacker: five addresses running
// one tool, and an office egress behind which one user ran the same tool. The
// five are reported; the office, whose traffic is overwhelmingly its other
// users', is not in the cluster -- a finding's addresses are what the closed
// loop rate-limits.
func TestGraphIntelligenceSparesAnOfficeWithOneAttacker(t *testing.T) {
	freshGraph(t)
	class := "t13d0000h1_222222222222_" + t.Name()
	const office = "10.44.1.1"
	now := time.Now()
	tf := newTraffic(35, now.Add(-10*time.Minute))
	tf.natEgress(office)
	tf.classAttacker(office, class, 3, now.Add(-time.Minute))
	for v := range 5 {
		tf.classAttacker(fmt.Sprintf("10.44.0.%d", v+1), class, 3, now.Add(-time.Minute))
	}
	data := tf.data()
	data.Now = now
	f := graphFinding(t, graphEngine().Analyze(t.Context(), data), class)
	if f == nil {
		t.Fatalf("five addresses with one tool were not reported because an office also used it")
	}
	if slices.Contains(f.GetSourceIps(), office) {
		t.Errorf("the office egress, 3 blocked requests among 800, is in the cluster: %v", f.GetSourceIps())
	}
}

// TestGraphIntelligenceDoesNotClusterAttackersHoursApart: the graph never
// decayed, so addresses arriving one per pass -- hours or days apart -- made
// one "coordinated" cluster. Five attackers with one tool, forty minutes apart,
// each still in the threat store when the last arrives, are not a campaign;
// the same five within minutes are.
func TestGraphIntelligenceDoesNotClusterAttackersHoursApart(t *testing.T) {
	for _, gap := range []time.Duration{40 * time.Minute, 2 * time.Minute} {
		freshGraph(t)
		class := fmt.Sprintf("t13d0000h1_333333333333_%s_%v", t.Name(), gap)
		start := time.Now().Add(-5 * gap)
		tf := newTraffic(36, start)
		var findings []*gateonv1.Anomaly
		for v := range 5 {
			at := start.Add(time.Duration(v) * gap)
			tf.classAttacker(fmt.Sprintf("10.45.0.%d", v+1), class, 3, at)
			data := tf.data()
			data.Now = at.Add(time.Minute)
			findings = graphEngine().Analyze(t.Context(), data)
		}
		f := graphFinding(t, findings, class)
		switch {
		case gap > attackEvidenceWindow && f != nil:
			t.Errorf("five attackers %v apart were reported as one campaign: %q", gap, f.GetDescription())
		case gap < attackEvidenceWindow && f == nil:
			t.Errorf("five attackers %v apart were not reported", gap)
		}
	}
}

// TestGraphIntelligenceSeesEdgesGossipedFromPeers: distributed mode is
// advertised as seeing a campaign spread across gateways. Peers sent only the
// ip -> fp edge and the detector read fp -> ip, so nothing a peer sent ever
// reached a detection. Now five peers' attack links, and no local evidence,
// make a cluster here.
func TestGraphIntelligenceSeesEdgesGossipedFromPeers(t *testing.T) {
	freshGraph(t)
	class := "t13d0000h1_444444444444_" + t.Name()
	delegate := &telemetry.ReputationDelegate{}
	for v := range 5 {
		msg, err := json.Marshal(&gateonv1.GraphEdgeSyncPayload{
			SourceNode: fmt.Sprintf("10.46.0.%d", v+1), TargetNode: "fp:" + class, Weight: 4, Type: "attack_evidence",
		})
		if err != nil {
			t.Fatal(err)
		}
		delegate.NotifyMsg(msg)
	}
	data := newTraffic(37, time.Now().Add(-10*time.Minute)).data()
	data.Now = time.Now()
	if f := graphFinding(t, graphEngine().Analyze(t.Context(), data), class); f == nil || f.GetClusterSize() != 5 {
		t.Errorf("five peers reported attackers behind %s; this node's detector found %v", class, f)
	}
}

// graphEngine is the engine with anomaly detection on and the per-address
// detector running too, as its fingerprint check was the other half of the
// browser-class finding.
func graphEngine() *AnomalyAnalysisEngine {
	return NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: sensitivityDefault},
	}, nil)
}

// graphFinding is the Graph Intelligence finding for class, or nil.
func graphFinding(t *testing.T, anomalies []*gateonv1.Anomaly, class string) *gateonv1.Anomaly {
	t.Helper()
	for _, a := range anomalies {
		if a.GetType() == graphCoordinatedType && a.GetJa4Plus() == class {
			return a
		}
	}
	return nil
}

// freshGraph gives the test an empty process-wide attack graph.
func freshGraph(t *testing.T) {
	t.Helper()
	telemetry.ResetAttackGraph()
	t.Cleanup(telemetry.ResetAttackGraph)
}
