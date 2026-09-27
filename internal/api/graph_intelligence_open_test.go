// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// OPEN: "Graph Intelligence" reports any five addresses that share a JA4+ value
// as a coordinated botnet, at a score applyAutomaticMitigation throttles in the
// kernel. JA4+ identifies a browser class, not a client (mem:reputation_identity,
// fingerprint.go), so what should make a cluster "coordinated" is a product
// decision. Run with: go test -tags openfinding -run GraphIntelligence ./internal/api/

// TestGraphIntelligenceDoesNotCallABrowserClassABotnet: five people load the
// same three pages with the same stock browser. Nothing about them is shared
// but the browser.
func TestGraphIntelligenceDoesNotCallABrowserClassABotnet(t *testing.T) {
	fp := "t13d1516h2_8daaf6152771_" + t.Name()
	var visitors []string
	data := &DiagnosticData{}
	base := time.Now().Add(-time.Minute)
	for v := range 5 {
		ip := fmt.Sprintf("10.40.0.%d", v+1)
		visitors = append(visitors, ip)
		for r, page := range []string{"/", "/app.js", "/style.css"} {
			tr := trace(ip, page, "200", 20, base.Add(time.Duration(v*3+r)*time.Second))
			tr.Fingerprint = fp
			data.Traces = append(data.Traces, tr)
		}
	}
	anomalies := analyzeWithAnomalyDetection(t, data)
	reportedAsBotnet(t, anomalies, fp, visitors)
}

// TestGraphIntelligenceClustersVisitorsDaysApart: the graph is process-global
// and never decays, so the same five visitors arriving one per detection pass
// -- hours or days apart -- make the same "coordinated" cluster.
func TestGraphIntelligenceClustersVisitorsDaysApart(t *testing.T) {
	fp := "t13d1516h2_8daaf6152771_" + t.Name()
	var visitors []string
	var anomalies []*gateonv1.Anomaly
	for v := range 5 {
		ip := fmt.Sprintf("10.41.0.%d", v+1)
		visitors = append(visitors, ip)
		tr := trace(ip, "/", "200", 20, time.Now().Add(-time.Duration(5-v)*24*time.Hour))
		tr.Fingerprint = fp
		anomalies = analyzeWithAnomalyDetection(t, &DiagnosticData{Traces: []*telemetry.TraceRecord{tr}})
	}
	reportedAsBotnet(t, anomalies, fp, visitors)
}

// TestGraphIntelligenceSeesEdgesGossipedFromPeers: distributed mode is
// advertised as detecting botnets that spread across nodes. Peers broadcast
// only the ip -> fp edge, and NotifyMsg stores only that direction, while the
// detector reads the fp -> ip neighbours of each "fp:" hub, so nothing a peer
// sends can ever reach a detection. (Whether it should, given the test above,
// is part of the same decision.)
func TestGraphIntelligenceSeesEdgesGossipedFromPeers(t *testing.T) {
	hub := "fp:t13d1516h2_8daaf6152771_" + t.Name()
	delegate := &telemetry.ReputationDelegate{}
	for v := range 5 {
		msg, err := json.Marshal(&gateonv1.GraphEdgeSyncPayload{
			SourceNode: fmt.Sprintf("10.42.0.%d", v+1), TargetNode: hub, Weight: 2, Type: "fp_ip",
		})
		if err != nil {
			t.Fatal(err)
		}
		delegate.NotifyMsg(msg)
	}
	if got := len(telemetry.GetGraphSnapshot()[hub]); got != 5 {
		t.Errorf("five peers reported addresses behind %s; the hub the detector reads holds %d of them", hub, got)
	}
}

func analyzeWithAnomalyDetection(t *testing.T, data *DiagnosticData) []*gateonv1.Anomaly {
	t.Helper()
	return NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: 0.5},
	}, nil).Analyze(t.Context(), data)
}

// reportedAsBotnet fails if any finding names fp as a coordinated or multi-IP
// attack, and says what applyAutomaticMitigation does with those findings.
func reportedAsBotnet(t *testing.T, anomalies []*gateonv1.Anomaly, fp string, visitors []string) {
	t.Helper()
	rec := &recordingLimiter{}
	(&ApiService{EbpfManager: rec}).applyAutomaticMitigation(context.Background(), anomalies)
	for _, a := range anomalies {
		coordinated := a.GetType() == "graph_coordinated_fp" && strings.Contains(a.GetDescription(), fp)
		multiIP := a.GetSource() == fp && strings.Contains(a.GetDescription(), "Multi-IP attack")
		if coordinated || multiIP {
			t.Errorf("%s (severity %s, score %.0f): %q; applyAutomaticMitigation throttled %d of the %d visitors to one packet per 10ms",
				a.GetType(), a.GetSeverity(), a.GetScore(), a.GetDescription(), rec.throttled(visitors), len(visitors))
		}
	}
}
