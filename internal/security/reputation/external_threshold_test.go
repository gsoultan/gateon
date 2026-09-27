// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The dashboard offers, for every external integration, a "Confidence
// Threshold -- Score above which to consider IP malicious", defaulting new
// integrations to 80. Nothing read it: GetExternalScore returned the highest raw
// score from any provider, and its only consumer, the security threat detector,
// applied a hard-coded 20. An operator who set 95 to cut noise, or 10 to catch
// more, changed nothing.
//
// Root cause in one sentence: the threshold was stored and displayed but the
// only comparison made was against a constant.

// externalLookup asks a store with one AbuseIPDB integration, at the given
// threshold, about an address the provider scores at answer.
func externalLookup(t *testing.T, threshold int32, answer int) (int, string) {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":` + strconv.Itoa(answer) + `}}`))
	}))
	t.Cleanup(provider.Close)

	store := NewIPReputationStore(&gateonv1.IPReputationConfig{
		Enabled: true,
		Integrations: []*gateonv1.IPReputationIntegration{{
			Id: "a", Name: "AbuseIPDB", Type: "abuseipdb", ApiKey: "k",
			Enabled: true, ConfidenceThreshold: threshold,
		}},
	})
	for _, p := range store.integrations {
		if c, ok := p.client.(*AbuseIPDBClient); ok {
			c.BaseURL = provider.URL
		}
	}
	return store.GetExternalScore(t.Context(), "203.0.113.240")
}

// TestTheConfidenceThresholdChangesSomething is the regression test.
func TestTheConfidenceThresholdChangesSomething(t *testing.T) {
	lowScore, lowProvider := externalLookup(t, 10, 50)
	highScore, highProvider := externalLookup(t, 95, 50)
	if lowScore == highScore && lowProvider == highProvider {
		t.Fatalf("a provider answering 50 gives (%d, %q) with the integration's confidence "+
			"threshold at 10 and at 95: the setting the dashboard offers is read by nothing",
			lowScore, lowProvider)
	}
	if lowScore != 50 || lowProvider != "AbuseIPDB" {
		t.Errorf("with the threshold at 10 an answer of 50 gives (%d, %q), want (50, \"AbuseIPDB\")", lowScore, lowProvider)
	}
	if highScore != 0 || highProvider != "" {
		t.Errorf("with the threshold at 95 an answer of 50 gives (%d, %q), want nothing", highScore, highProvider)
	}
}

// TestTheThresholdIsTheScoreAboveWhichAnAnswerCounts pins the boundary the
// dashboard's wording sets: "above", so an answer equal to the threshold does
// not count.
func TestTheThresholdIsTheScoreAboveWhichAnAnswerCounts(t *testing.T) {
	if got, _ := externalLookup(t, 50, 50); got != 0 {
		t.Errorf("an answer equal to the threshold counted (%d)", got)
	}
	if got, _ := externalLookup(t, 50, 51); got != 51 {
		t.Errorf("an answer above the threshold gave %d, want 51", got)
	}
}

// TestAnUnsetThresholdKeepsTheOldFloor: an integration saved without a
// threshold -- 0, proto3's unset -- counts what the detector's hard-coded 20
// counted, so an install that never set one detects exactly what it did.
func TestAnUnsetThresholdKeepsTheOldFloor(t *testing.T) {
	if got, _ := externalLookup(t, 0, 20); got != 0 {
		t.Errorf("with no threshold set an answer of 20 counted (%d); the old floor was above 20", got)
	}
	if got, _ := externalLookup(t, 0, 21); got != 21 {
		t.Errorf("with no threshold set an answer of 21 gave %d, want 21", got)
	}
}
