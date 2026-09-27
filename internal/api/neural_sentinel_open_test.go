// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package api

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/e-XpertSolutions/go-iforest/v2/iforest"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// OPEN: the Neural Sentinel has never reported anything. Fixing it turns on an
// outlier detector whose findings applyAutomaticMitigation throttles in the
// kernel, so whether to fix it, and on what terms, is a product decision.
// Run with: go test -tags openfinding -run NeuralSentinel ./internal/api/

// TestNeuralSentinelReportsAGrossOutlier asks the detector for the one thing an
// isolation forest is for: one client out of forty-one probing two hundred
// paths that do not exist, at the dashboard's highest sensitivity.
func TestNeuralSentinelReportsAGrossOutlier(t *testing.T) {
	const scanner = "10.20.9.9"
	data := visitorsAndScanner(scanner)
	engine := NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Enabled: true, Sensitivity: 1},
	}, nil)
	for _, a := range engine.Analyze(t.Context(), data) {
		if a.GetType() == "neural_sentinel" && a.GetSource() == scanner {
			return
		}
	}
	// Why: the detector trains and then calls Predict, which refuses to run on a
	// forest that has not been through Test. Detect returns nil on the error.
	forest := iforest.NewForest(100, 256, 0.05)
	features := neuralFeatures(data)
	forest.Train(features)
	_, _, err := forest.Predict(features)
	t.Errorf("no neural_sentinel finding for a client probing 200 missing paths among %d visitors; "+
		"the forest the detector builds refuses to score: %v", len(features)-1, err)
}

// TestNeuralSentinelScoresCanReachItsThreshold is the second reason, which
// fixing the first would expose: go-iforest's score is 0.5 - 2^(-E(h)/c(n)),
// in [-0.5, 0.5) with anomalies at the LOW end, while the detector reports a
// score above 0.9 - Sensitivity/100*0.4 -- 0.896 at the dashboard's highest
// sensitivity, 1.0, because that formula assumes a 0-100 scale the dashboard
// does not use.
func TestNeuralSentinelScoresCanReachItsThreshold(t *testing.T) {
	const scanner = "10.20.9.9"
	data := visitorsAndScanner(scanner)
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	features := neuralFeatures(data)

	forest := iforest.NewForest(100, 256, 0.05)
	forest.Train(features)
	if err := forest.Test(features); err != nil {
		t.Fatal(err)
	}
	_, scores, err := forest.Predict(features)
	if err != nil {
		t.Fatal(err)
	}
	threshold := 0.9 - (1.0 / 100.0 * 0.4) // the detector's formula at Sensitivity 1
	scannerScore := scores[len(scores)-1]  // neuralFeatures puts the scanner last
	if scannerScore <= threshold {
		t.Errorf("the scanner scores %.3f and every visitor scores at least %.3f; the detector reports scores "+
			"above %.3f, a value this library cannot produce", scannerScore, minOf(scores[:len(scores)-1]), threshold)
	}
}

// visitorsAndScanner is forty identical visitors and one scanner, in time
// order, the scanner's traces last.
func visitorsAndScanner(scanner string) *DiagnosticData {
	data := &DiagnosticData{}
	base := time.Now().Add(-10 * time.Minute)
	pages := []string{"/", "/app.js", "/style.css"}
	for v := range 40 {
		for r := range 10 {
			data.Traces = append(data.Traces, trace(fmt.Sprintf("10.20.0.%d", v+1), pages[r%3], "200", 20,
				base.Add(time.Duration(v*10+r)*time.Second)))
		}
	}
	for r := range 200 {
		data.Traces = append(data.Traces, trace(scanner, fmt.Sprintf("/probe-%d.php", r), "404", 2,
			base.Add(time.Duration(r)*100*time.Millisecond)))
	}
	return data
}

// neuralFeatures is the detector's feature matrix, rows in the order the
// clients first appear in data.Traces.
func neuralFeatures(data *DiagnosticData) [][]float64 {
	d := &NeuralAnomalyDetector{}
	seen := map[string]bool{}
	var out [][]float64
	for _, tr := range data.Traces {
		if seen[tr.SourceIP] {
			continue
		}
		seen[tr.SourceIP] = true
		if st := data.IPStats[tr.SourceIP]; st != nil && st.TotalRequests >= 5 {
			out = append(out, d.extractFeatures(st))
		}
	}
	return out
}

func minOf(xs []float64) float64 {
	m := math.Inf(1)
	for _, x := range xs {
		m = math.Min(m, x)
	}
	return m
}
