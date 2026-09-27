// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// HybridGraphAnomalyDetector -- "Graph Intelligence" -- reports a campaign:
// several addresses, each caught attacking in the last half hour, presenting
// one client class, where the class is not simply a browser most of whose
// users are innocent.
//
// A shared JA4+ value is not evidence of coordination: it names a client class
// -- a TLS stack, a browser build and its header habits -- that everyone on
// the same Chrome shares (mem:reputation_identity). The detector used to report
// any five addresses sharing one as a botnet, at a score the diagnostics loop
// throttled in the kernel. Now every address in a cluster needs attack evidence
// of its own (attackEvidenceWeight), which fades once it stops being renewed
// (telemetry.AttackClusters), and the evidenced addresses must be most of the
// class's addresses in the analysis window.
type HybridGraphAnomalyDetector struct {
	Config *gateonv1.AnomalyDetectionConfig
}

const (
	graphCoordinatedType = "graph_coordinated_fp"
	// graphMinCluster is the fewest evidenced addresses a campaign has.
	graphMinCluster = 5
	// graphMinEvidencedShare is the share of a class's addresses that must be
	// evidenced: below it the class is a browser with a few bad users on it.
	graphMinEvidencedShare = 0.5
	// graphMaxBroadcastsPerPass bounds what one pass gossips, since graph links
	// share the gossip queue with reputation updates.
	graphMaxBroadcastsPerPass = 64
)

// graphIntelligenceRuns reports whether the detector runs under cfg: whenever
// anomaly detection is on. It reads the attack evidence threats carry, so it
// does not need behavioural fingerprinting.
func graphIntelligenceRuns(cfg *gateonv1.AnomalyDetectionConfig) bool {
	return cfg.GetEnabled()
}

// DetectorStatus reports whether the analysis loop runs the Neural Sentinel and
// Graph Intelligence under cfg -- the conditions each checks before it runs --
// for the status the dashboard shows.
func DetectorStatus(cfg *gateonv1.AnomalyDetectionConfig) (neuralSentinel, graphIntelligence bool) {
	_, neuralSentinel = neuralThreshold(cfg)
	return neuralSentinel, graphIntelligenceRuns(cfg)
}

// Detect files this pass's attack links, gossips the qualifying ones, and
// reports the clusters.
func (d *HybridGraphAnomalyDetector) Detect(ctx context.Context, data *DiagnosticData) []*gateonv1.Anomaly {
	if !graphIntelligenceRuns(d.Config) {
		return nil
	}
	now := data.now()
	links := attackLinksInWindow(data, now)
	for _, l := range links {
		// As of now, not as of the newest threat: the evidence is a count over
		// the window ending now, and it fades only once a pass stops seeing it
		// -- when its threats age out of the window, or out of the latest
		// thousand on a busy gateway.
		telemetry.ObserveAttackLink(l.class, l.ip, l.evidence, now)
	}
	broadcastAttackLinks(data, links)

	presenters := classPresenters(data)
	var findings []*gateonv1.Anomaly
	for _, c := range telemetry.AttackClusters(now, graphMinCluster, harmMinAttackWeight) {
		if f := clusterFinding(data, c, presenters[c.Fingerprint]); f != nil {
			populateAnomalyGeo(ctx, f, f.GetSourceIps()[0])
			findings = append(findings, f)
		}
	}
	return findings
}

// observedLink is one address's attack evidence under one client class in
// this pass's threats.
type observedLink struct {
	class, ip string
	evidence  float64
}

// attackLinksInWindow sums each (class, address) pair's attack evidence over
// the threats of the evidence window.
func attackLinksInWindow(data *DiagnosticData, now time.Time) []observedLink {
	since := now.Add(-attackEvidenceWindow)
	byPair := make(map[[2]string]*observedLink)
	for _, th := range data.SecurityThreats {
		weight := attackEvidenceWeight(th)
		if weight == 0 || th.Fingerprint == "" || th.SourceIP == "" || th.Time.Before(since) {
			continue
		}
		key := [2]string{th.Fingerprint, th.SourceIP}
		l := byPair[key]
		if l == nil {
			l = &observedLink{class: th.Fingerprint, ip: th.SourceIP}
			byPair[key] = l
		}
		l.evidence += weight
	}
	links := make([]observedLink, 0, len(byPair))
	for _, l := range byPair {
		links = append(links, *l)
	}
	slices.SortFunc(links, func(a, b observedLink) int { return cmp.Compare(b.evidence, a.evidence) })
	return links
}

// broadcastAttackLinks gossips the pass's strongest qualifying links, at most
// graphMaxBroadcastsPerPass of them. A link qualifies here as it does in a
// cluster, so a peer is never sent what this node would not count itself.
func broadcastAttackLinks(data *DiagnosticData, links []observedLink) {
	sent := 0
	for _, l := range links {
		if sent == graphMaxBroadcastsPerPass || l.evidence < harmMinAttackWeight {
			return
		}
		if mostlyAttacks(data, l.ip) {
			telemetry.BroadcastAttackLink(l.class, l.ip, l.evidence)
			sent++
		}
	}
}

// mostlyAttacks reports whether the address's traffic in this window is
// dominated by attacks, as harmEvidence requires of an address before
// anything can throttle it: one address can carry an office, and one bad user
// behind it is not a reason to rate-limit the rest. An address with no traced
// requests in the window -- blocked before it was traced, or seen only by a
// peer -- has nothing to weigh its evidence against, and the evidence stands.
func mostlyAttacks(data *DiagnosticData, ip string) bool {
	st := data.IPStats[ip]
	if st == nil || st.TotalRequests == 0 {
		return true
	}
	return st.AttackEvidence/st.estimatedRequests(data.TraceSampleRate) >= harmMinAttackShare
}

// classPresenters is, per client class, the addresses that presented it in
// this window's traces. The class of a trace is the fingerprint recorded with
// it, or else JA4 and JA4H joined as the request path joins them into JA4+.
func classPresenters(data *DiagnosticData) map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{})
	for _, tr := range data.Traces {
		class := tr.Fingerprint
		if class == "" && (tr.JA4 != "" || tr.JA4H != "") {
			class = tr.JA4 + "_" + tr.JA4H
		}
		if class == "" || tr.SourceIP == "" {
			continue
		}
		if out[class] == nil {
			out[class] = make(map[string]struct{})
		}
		out[class][tr.SourceIP] = struct{}{}
	}
	return out
}

// clusterFinding is the anomaly for a cluster, or nil when, once each
// address's own traffic is weighed, it is not a campaign.
func clusterFinding(data *DiagnosticData, c telemetry.AttackCluster, presenters map[string]struct{}) *gateonv1.Anomaly {
	addresses := make([]string, 0, len(c.Addresses))
	for _, ip := range c.Addresses {
		if mostlyAttacks(data, ip) {
			addresses = append(addresses, ip)
		}
	}
	if len(addresses) < graphMinCluster {
		return nil
	}
	population := len(presenters)
	for _, ip := range addresses {
		if _, presented := presenters[ip]; !presented {
			population++
		}
	}
	share := float64(len(addresses)) / float64(population)
	if share < graphMinEvidencedShare {
		return nil
	}
	score := 50 + 50*share*math.Min(1, float64(len(addresses))/10)
	return &gateonv1.Anomaly{
		Type:     graphCoordinatedType,
		Severity: severityHigh,
		Description: fmt.Sprintf("Graph Intelligence: %d addresses presenting one client class were each caught "+
			"attacking in the last %.0f minutes, and they are %d of the %d addresses that presented it: one campaign's "+
			"tooling, not visitors who share a browser.", len(addresses), attackEvidenceWindow.Minutes(), len(addresses), population),
		Source:      strings.Join(addresses, ", "),
		SourceIps:   addresses,
		Ja4Plus:     c.Fingerprint,
		Score:       score,
		Confidence:  score / 100,
		ClusterSize: int32(len(addresses)),
		Timestamp:   c.Newest.Format(time.RFC3339),
		Recommendation: "Every address listed was blocked by the WAF, sprang a trap or was caught guessing " +
			"credentials. Repeated findings rate-limit them in the kernel (where eBPF is attached); releasing an " +
			"address's mitigation lifts its limit and resets that history.",
	}
}
