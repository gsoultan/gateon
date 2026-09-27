// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package reputation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// OPEN FINDING -- needs a product decision, see the reviewer report.
//
// TestTheConfidenceThresholdChangesSomething: the dashboard offers, for every
// external integration, a "Confidence Threshold -- Score above which to
// consider IP malicious", defaulting new integrations to 80. Nothing reads it:
// GetExternalScore returns the highest raw score from any provider, and its
// only consumer, the security threat detector, applies a hard-coded 20. An
// operator who set 95 to cut noise, or 10 to catch more, changed nothing.
// Whether to apply the configured value (which re-tunes detection on every
// install that kept the default 80) or to remove the field is the decision.
func TestTheConfidenceThresholdChangesSomething(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":50}}`))
	}))
	t.Cleanup(provider.Close)

	lookup := func(threshold int32) (int, string) {
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

	lowScore, lowProvider := lookup(10)
	highScore, highProvider := lookup(95)
	if lowScore == highScore && lowProvider == highProvider {
		t.Fatalf("a provider answering 50 gives (%d, %q) with the integration's confidence "+
			"threshold at 10 and at 95: the setting the dashboard offers is read by nothing",
			lowScore, lowProvider)
	}
}
