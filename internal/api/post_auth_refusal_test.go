// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestRefusedPOSTsCountAsGuessingOnlyWhenTheRefusalCouldBeOne: the analysis
// engine's credential-guessing shape -- many POSTs answered 401/403, which
// gates the Neural Sentinel and Graph findings and from them the kernel
// throttle -- counted every refused POST, whatever the refusal mark said
// (review 3, F5). A poller re-presenting an expired session over Connect or
// gRPC-Web (refusal "token", ADR 0031) and a shunned address's own refused
// POSTs (refusal "mitigation", the shape where a shun renews itself) read as
// twelve guesses in twelve requests. credentialAttempt already excluded both;
// the count beside it now applies the same rule.
func TestRefusedPOSTsCountAsGuessingOnlyWhenTheRefusalCouldBeOne(t *testing.T) {
	const ip, posts = "100.64.70.1", 12
	for _, tc := range []struct {
		refusal      request.Refusal
		serviceDelay float64 // ms the router spent in a backend; 0 = none reached
		counted      bool
	}{
		{request.RefusalNone, 3, true},           // a backend's login form, or Basic auth
		{request.RefusalNone, 0, false},          // the WAF or geofence, before any backend
		{request.RefusalAuthentication, 0, true}, // the gateway's authentication refused it
		{request.RefusalToken, 0, false},
		{request.RefusalMitigation, 0, false},
	} {
		data := &DiagnosticData{}
		start := time.Now().Add(-5 * time.Minute)
		for i := range posts {
			data.Traces = append(data.Traces, &telemetry.TraceRecord{
				SourceIP: ip, Method: http.MethodPost, Path: "/rpc/gateon.v1.Service/Poll", Status: "401",
				Refusal: tc.refusal.String(), ServiceDelay: tc.serviceDelay,
				Timestamp: start.Add(time.Duration(i) * time.Second),
			})
		}
		(&AnomalyAnalysisEngine{}).aggregate(data)
		stats := data.IPStats[ip]

		want := 0
		if tc.counted {
			want = posts
		}
		if stats.PostAuthFailures != want || stats.CredentialFailures != want {
			t.Errorf("refusal %q, %vms in a backend: PostAuthFailures=%d CredentialFailures=%d, want %d each",
				tc.refusal, tc.serviceDelay, stats.PostAuthFailures, stats.CredentialFailures, want)
		}
		if why, harmful := stats.harmEvidence(1); harmful != tc.counted {
			t.Errorf("refusal %q, %vms in a backend: harmful=%v (%q), want %v",
				tc.refusal, tc.serviceDelay, harmful, why, tc.counted)
		}
	}
}
