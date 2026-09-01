// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func anomaly(sev string, score float64) *gateonv1.Anomaly {
	return &gateonv1.Anomaly{Severity: sev, Score: score, Description: fmt.Sprintf("%s/%.0f", sev, score)}
}

// A pass under the cap must be returned untouched, including its order: sorting
// unconditionally would reorder the Diagnostics view for no reason.
func TestUnderTheCapNothingIsChanged(t *testing.T) {
	in := []*gateonv1.Anomaly{anomaly("low", 1), anomaly("critical", 9), anomaly("high", 5)}
	got := capAnomalies(in)

	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].GetSeverity() != "low" {
		t.Errorf("order changed under the cap: got %q first", got[0].GetSeverity())
	}
}

// TestOverTheCapKeepsTheMostSevere is the point of the change. Truncating an
// unordered slice would drop findings at random, so a pass that overflows must
// keep its worst, not its first.
func TestOverTheCapKeepsTheMostSevere(t *testing.T) {
	var in []*gateonv1.Anomaly
	// Fill past the cap with the least serious severity...
	for i := 0; i < maxAnomaliesPerPass+50; i++ {
		in = append(in, anomaly("low", 0))
	}
	// ...then append the findings that must survive, at the very end where a
	// naive truncation would discard them.
	in = append(in, anomaly("critical", 9), anomaly("high", 7))

	got := capAnomalies(in)

	if len(got) != maxAnomaliesPerPass {
		t.Fatalf("len = %d, want the cap of %d", len(got), maxAnomaliesPerPass)
	}
	if got[0].GetSeverity() != "critical" {
		t.Errorf("first kept = %q, want the critical finding", got[0].GetSeverity())
	}
	if got[1].GetSeverity() != "high" {
		t.Errorf("second kept = %q, want the high finding", got[1].GetSeverity())
	}
}

func TestSeverityRanksWorstFirst(t *testing.T) {
	order := []string{"critical", "high", "medium", "low"}
	for i := 0; i < len(order)-1; i++ {
		if severityRank(order[i]) <= severityRank(order[i+1]) {
			t.Errorf("%q does not outrank %q", order[i], order[i+1])
		}
	}
	// "warning" is emitted by some detectors and must not fall below "low".
	if severityRank("warning") <= severityRank("low") {
		t.Error(`"warning" ranked at or below "low"`)
	}
	if severityRank("CRITICAL") != severityRank("critical") {
		t.Error("severity ranking is case sensitive")
	}
}

// An unknown severity must sort last. Ranking it first would let a typo in one
// detector push real critical findings out of a truncated pass.
func TestUnknownSeverityRanksLast(t *testing.T) {
	if severityRank("banana") != 0 {
		t.Errorf("unknown severity rank = %d, want 0", severityRank("banana"))
	}
	if severityRank("") != 0 {
		t.Errorf("empty severity rank = %d, want 0", severityRank(""))
	}

	var in []*gateonv1.Anomaly
	for i := 0; i < maxAnomaliesPerPass; i++ {
		in = append(in, anomaly("banana", 100))
	}
	in = append(in, anomaly("critical", 0))

	got := capAnomalies(in)
	if got[0].GetSeverity() != "critical" {
		t.Errorf("first kept = %q, want critical to outrank an unknown severity", got[0].GetSeverity())
	}
}

// Equal severities fall back to score, so the strongest signal survives.
func TestEqualSeveritiesOrderByScore(t *testing.T) {
	var in []*gateonv1.Anomaly
	for i := 0; i < maxAnomaliesPerPass; i++ {
		in = append(in, anomaly("high", 1))
	}
	in = append(in, anomaly("high", 99))

	if got := capAnomalies(in); got[0].GetScore() != 99 {
		t.Errorf("first kept score = %v, want the highest-scoring finding", got[0].GetScore())
	}
}

// floodDetector emits more anomalies than a pass may return, so the engine has
// to apply the cap itself.
type floodDetector struct{ n int }

func (f *floodDetector) Detect(context.Context, *DiagnosticData) []*gateonv1.Anomaly {
	out := make([]*gateonv1.Anomaly, 0, f.n)
	for i := 0; i < f.n; i++ {
		out = append(out, anomaly("low", 0))
	}
	out = append(out, anomaly("critical", 9))
	return out
}

// TestAnalyzeAppliesTheCap guards the wiring, not the helper.
//
// Asserting on capAnomalies alone still passes if Analyze stops calling it,
// which is exactly the regression worth preventing: the bound would silently
// stop applying while every unit test stayed green.
func TestAnalyzeAppliesTheCap(t *testing.T) {
	e := &AnomalyAnalysisEngine{detectors: []AnomalyDetector{&floodDetector{n: maxAnomaliesPerPass + 100}}}

	got := e.Analyze(context.Background(), &DiagnosticData{})

	if len(got) > maxAnomaliesPerPass {
		t.Fatalf("Analyze returned %d anomalies, above the cap of %d", len(got), maxAnomaliesPerPass)
	}
	if got[0].GetSeverity() != "critical" {
		t.Errorf("first result = %q, want the critical finding kept", got[0].GetSeverity())
	}
}
