// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"slices"
	"strings"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The Neural Sentinel had never reported anything: Predict refuses a forest
// that has not been through Test, the library's scores run the other way from
// the detector's threshold, and the threshold read the dashboard's 0..1
// Sensitivity as 0..100. Found by the 2026-09-27 AI-analysis review as open
// findings; fixed with them.
//
// The forest draws from math/rand's global source, which go-iforest gives no
// way to seed. These tests are deterministic by margin instead: every
// population here was scored 300 times (probe, not committed) and the bar each
// test relies on sits at least four standard deviations from the nearest
// score. The file is run with -count=50 to show it.

const (
	sensitivityDefault = 0.5
	sensitivityHighest = 1.0
)

// TestNeuralSentinelReportsAGrossOutlier asks for the one thing an isolation
// forest is for: one client among forty browsers probing two hundred paths that
// do not exist, ten of its requests blocked by the WAF. It scored 0.83 at the
// least over 300 runs; the bar is 0.70 at the default and 0.65 at the highest
// setting.
func TestNeuralSentinelReportsAGrossOutlier(t *testing.T) {
	const scanner = "10.51.0.1"
	for _, s := range []float64{sensitivityDefault, sensitivityHighest} {
		tf := newTraffic(21, time.Now().Add(-10*time.Minute))
		tf.browsers("10.50", 40)
		tf.scanner(scanner, 200, 10)
		if f := neuralFindingFor(t, tf, s, scanner); f == nil {
			t.Errorf("sensitivity %.1f: no neural_sentinel finding for a client probing 200 missing paths among 40 browsers", s)
		}
	}
}

// TestNeuralSentinelReportsCredentialStuffing: a script POSTing a credential
// list to /login every 600ms among thirty browsers. 0.77 at the least over 300
// runs, against 0.70.
func TestNeuralSentinelReportsCredentialStuffing(t *testing.T) {
	const stuffer = "10.51.0.2"
	tf := newTraffic(23, time.Now().Add(-10*time.Minute))
	tf.browsers("10.50", 30)
	tf.credentialStuffer(stuffer, 100)
	f := neuralFindingFor(t, tf, sensitivityDefault, stuffer)
	if f == nil {
		t.Fatalf("no neural_sentinel finding for a client failing 95 logins in a minute among 30 browsers")
	}
	if !strings.Contains(f.GetDescription(), "POSTs refused with 401/403") {
		t.Errorf("the finding does not say why the traffic is harmful: %q", f.GetDescription())
	}
}

// TestNeuralSentinelDoesNotDependOnWhoComesFirst: asked for a 256-row
// subsample from fewer clients, go-iforest pads every tree's sample with row 0.
// Whoever comes first is then a couple of hundred identical points in every
// tree -- the densest region of the data, the last thing the forest isolates.
// When the scanner comes first, it hides behind its own copies.
func TestNeuralSentinelDoesNotDependOnWhoComesFirst(t *testing.T) {
	const scanner = "10.0.0.1" // sorts before every browser
	tf := newTraffic(21, time.Now().Add(-10*time.Minute))
	tf.browsers("10.50", 40)
	tf.scanner(scanner, 200, 10)
	if f := neuralFindingFor(t, tf, sensitivityDefault, scanner); f == nil {
		t.Errorf("the scanner went unreported when its address was the population's first row")
	}
}

// TestNeuralSentinelScoresCanReachItsThreshold: the detector compares the
// library's scores with its threshold, so both have to be on the same scale.
// The library reports 0.5 - 2^(-E(h)/c(n)), with anomalies LOW; the detector
// reported scores ABOVE 0.896. Now the scores are the standard ones and the
// outlier clears every setting's bar while the browsers stay near 0.5.
func TestNeuralSentinelScoresCanReachItsThreshold(t *testing.T) {
	const scanner = "10.51.0.1"
	tf := newTraffic(21, time.Now().Add(-10*time.Minute))
	tf.browsers("10.50", 40)
	tf.scanner(scanner, 200, 10)
	data := tf.data()
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	pop := neuralPopulation(data)
	scores, err := isolationScores(pop.features)
	if err != nil {
		t.Fatalf("the forest the detector builds refuses to score: %v", err)
	}
	at := slices.Index(pop.ips, scanner)
	lowestBar, _ := neuralThreshold(&gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: 0.01})
	if scores[at] < lowestBar {
		t.Errorf("the scanner scores %.3f; the least sensitive setting reports from %.3f", scores[at], lowestBar)
	}
	for i, s := range scores {
		if i != at && s > 0.65 {
			t.Errorf("browser %s scores %.3f, as high as the most sensitive bar", pop.ips[i], s)
		}
	}
}

// TestNeuralSentinelThresholdFollowsTheDashboardsSensitivity: the slider runs
// 0..1 and ships at 0.5. Read as 0..100 it put every setting's bar near 0.9.
func TestNeuralSentinelThresholdFollowsTheDashboardsSensitivity(t *testing.T) {
	previous := 1.0
	for _, s := range []float64{0.01, 0.25, 0.5, 0.75, 1} {
		bar, on := neuralThreshold(&gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: s})
		if !on || bar < 0.65 || bar > 0.75 {
			t.Errorf("sensitivity %.2f: bar %.3f (on %v), want within [0.65, 0.75]", s, bar, on)
		}
		if bar >= previous {
			t.Errorf("sensitivity %.2f: bar %.3f is not below the bar at the setting beneath it (%.3f)", s, bar, previous)
		}
		previous = bar
	}
	for name, cfg := range map[string]*gateonv1.AnomalyDetectionConfig{
		"sensitivity 0": {Enabled: true, Sensitivity: 0}, "anomaly detection off": {Enabled: false, Sensitivity: 0.5},
		"no configuration": nil,
	} {
		if _, on := neuralThreshold(cfg); on {
			t.Errorf("%s: the detector runs", name)
		}
	}
}

// TestNeuralSentinelLeavesAHomogeneousPopulationAlone: a threshold relative to
// the population -- the library's labels mark its lowest-scoring 5% -- reports
// someone in any crowd. An absolute one reports no one where no one stands out:
// not among 150 browsers, and not in an identity-provider outage where every
// client is failing its logins, which is harmful traffic, so only the forest's
// bar stands between it and a throttle. The highest crowd score over 300 runs
// was 0.59; the bar here is the most sensitive, 0.65.
func TestNeuralSentinelLeavesAHomogeneousPopulationAlone(t *testing.T) {
	crowds := map[string]func(tf *traffic){
		"150 browsers":                     func(tf *traffic) { tf.browsers("10.50", 150) },
		"40 clients during an auth outage": func(tf *traffic) { tf.authOutage("10.53", 40) },
	}
	for name, build := range crowds {
		tf := newTraffic(28, time.Now().Add(-10*time.Minute))
		build(tf)
		data := tf.data()
		for _, a := range neuralEngine(sensitivityHighest).Analyze(t.Context(), data) {
			if a.GetType() == neuralSentinelType {
				t.Errorf("%s: %s", name, a.GetDescription())
			}
		}
	}
	// The outage's clients are all harmful, so the forest's bar is what the
	// test above exercises; without this it could pass on the harm gate alone.
	tf := newTraffic(28, time.Now().Add(-10*time.Minute))
	tf.authOutage("10.53", 40)
	data := tf.data()
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	for ip, st := range data.IPStats {
		if _, harmful := st.harmEvidence(1); !harmful {
			t.Fatalf("precondition: outage client %s is not harmful traffic", ip)
		}
	}
}

// TestNeuralSentinelLeavesUnusualButBenignClientsAlone: a dashboard polling
// every 5s, a health checker, a CI runner, an office's egress and a tab polling
// into 401s after its session expired. The forest isolates several of them --
// the expired tab scored at least 0.73 over 300 runs, the CI runner 0.68 --
// past even the default bar. None of them is harmful, and none is reported.
func TestNeuralSentinelLeavesUnusualButBenignClientsAlone(t *testing.T) {
	benign := map[string]string{
		"10.52.0.1": "dashboard polling every 5s", "10.52.0.2": "health checker", "10.52.0.3": "CI runner",
		"10.52.0.4": "office egress", "10.52.0.5": "tab polling into 401s",
	}
	tf := newTraffic(24, time.Now().Add(-10*time.Minute))
	tf.browsers("10.50", 40)
	tf.poller("10.52.0.1", "/api/status", 5*time.Second, 120)
	tf.poller("10.52.0.2", "/healthz", 10*time.Second, 60)
	tf.ciRunner("10.52.0.3")
	tf.natEgress("10.52.0.4")
	tf.expiredSessionPoller("10.52.0.5", "/api/status", 5*time.Second, 120)

	for _, a := range neuralEngine(sensitivityHighest).Analyze(t.Context(), tf.data()) {
		if who, ok := benign[a.GetSource()]; ok && a.GetType() == neuralSentinelType {
			t.Errorf("%s was reported: %s", who, a.GetDescription())
		}
	}
	// And the forest did isolate one of them: this is the harm gate's test.
	data := tf.data()
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	pop := neuralPopulation(data)
	scores, err := isolationScores(pop.features)
	if err != nil {
		t.Fatal(err)
	}
	if s := scores[slices.Index(pop.ips, "10.52.0.5")]; s < 0.65 {
		t.Fatalf("precondition: the expired tab scored %.3f, under every bar; the test above proves nothing", s)
	}
}

// TestNeuralSentinelSkipsThePassUnderLowPower: under CPU pressure the pass is
// skipped rather than run with a quarter of the trees and twice the noise.
func TestNeuralSentinelSkipsThePassUnderLowPower(t *testing.T) {
	tf := newTraffic(21, time.Now().Add(-10*time.Minute))
	tf.browsers("10.50", 40)
	tf.scanner("10.51.0.1", 200, 10)
	engine := neuralEngine(sensitivityDefault)
	engine.SetLowPower(true)
	for _, a := range engine.Analyze(t.Context(), tf.data()) {
		if a.GetType() == neuralSentinelType {
			t.Errorf("low power, and the forest ran anyway: %s", a.GetDescription())
		}
	}
}

// neuralEngine is the engine with anomaly detection on at sensitivity s.
func neuralEngine(s float64) *AnomalyAnalysisEngine {
	return NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: s},
	}, nil)
}

// neuralFindingFor runs the population through the engine at sensitivity s
// and returns ip's neural_sentinel finding, or nil.
func neuralFindingFor(t *testing.T, tf *traffic, s float64, ip string) *gateonv1.Anomaly {
	t.Helper()
	for _, a := range neuralEngine(s).Analyze(t.Context(), tf.data()) {
		if a.GetType() == neuralSentinelType && a.GetSource() == ip {
			return a
		}
	}
	return nil
}
