// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/reputation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestTheDetectorUsesTheIntegrationsConfidenceThreshold: the security threat
// detector counted an external provider's answer only above a hard-coded 20,
// whatever the integration's "Confidence Threshold" said. The threshold is now
// applied where the answers are gathered, and the detector takes what clears
// it -- so a threshold of 10 lets an answer of 15 count, and one of 95 keeps an
// answer of 50 out, both of which the constant decided the other way.
func TestTheDetectorUsesTheIntegrationsConfidenceThreshold(t *testing.T) {
	for _, tc := range []struct {
		threshold int32
		answer    int
		counted   bool
	}{
		{threshold: 10, answer: 15, counted: true},
		{threshold: 95, answer: 50, counted: false},
		{threshold: 0, answer: 21, counted: true}, // unset: the old floor of 20
		{threshold: 0, answer: 20, counted: false},
	} {
		name := "threshold " + strconv.Itoa(int(tc.threshold)) + ", answer " + strconv.Itoa(tc.answer)
		t.Run(name, func(t *testing.T) {
			const ip = "203.0.113.241"
			d := &SecurityThreatDetector{Threshold: 5, Reputation: externalFeed(t, tc.threshold, tc.answer)}
			data := &DiagnosticData{IPStats: map[string]*IPStats{ip: {TotalRequests: 11, LastSeen: time.Now()}}}

			counted := false
			for _, a := range d.Detect(t.Context(), data) {
				if a.Source == ip && strings.Contains(a.Description, "External threat feed (AbuseIPDB)") {
					counted = true
				}
			}
			if counted != tc.counted {
				t.Errorf("the provider's answer of %d counted=%v with the integration's threshold at %d, want %v",
					tc.answer, counted, tc.threshold, tc.counted)
			}
		})
	}
}

// externalFeed is a reputation store with one AbuseIPDB integration at the
// given threshold, whose provider scores every address at answer.
//
// The provider is reached through http.DefaultTransport, replaced for the
// test's duration: the store builds its clients itself and the client's
// address is not reachable from this package, and nothing in this package runs
// in parallel (geo_enrichment_open_test.go does the same).
func externalFeed(t *testing.T, threshold int32, answer int) *reputation.IPReputationStore {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = abuseIPDBAnswering(answer)
	t.Cleanup(func() { http.DefaultTransport = prev })
	return reputation.NewIPReputationStore(&gateonv1.IPReputationConfig{
		Enabled: true,
		Integrations: []*gateonv1.IPReputationIntegration{{
			Id: "a", Name: "AbuseIPDB", Type: "abuseipdb", ApiKey: "k",
			Enabled: true, ConfidenceThreshold: threshold,
		}},
	})
}

// abuseIPDBAnswering answers AbuseIPDB's check endpoint with a fixed
// confidence score and refuses anything else.
type abuseIPDBAnswering int

func (a abuseIPDBAnswering) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "api.abuseipdb.com" {
		return nil, fmt.Errorf("unexpected request to %s", r.URL)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"data":{"abuseConfidenceScore":` + strconv.Itoa(int(a)) + `}}`)),
		Request:    r,
	}, nil
}
