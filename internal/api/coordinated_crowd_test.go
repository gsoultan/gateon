// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The coordinated-attack detectors read shape alone: addresses following one
// path sequence with one browser, or sharing one set of paths. Under heavy
// legitimate traffic those shapes are the norm -- a push notification sends
// one app on one phone model through one flow, and every visitor of a
// single-page application loads the same assets -- so both reported crowds as
// campaigns, at high severity, with a recommendation to block them. Root
// cause: low identifier entropy and a shared footprint were taken as evidence
// when they are only multipliers; a campaign is told by what it leaves behind.

func coordinatedFindings(t *testing.T, traces []*telemetry.TraceRecord) []*gateonv1.Anomaly {
	t.Helper()
	engine := NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{SecurityThreatThreshold: 10.0},
	}, nil)
	var found []*gateonv1.Anomaly
	for _, a := range engine.Analyze(context.Background(), &DiagnosticData{Traces: traces}) {
		if a.GetType() == "coordinated_attack" {
			found = append(found, a)
		}
	}
	return found
}

func TestAFlashCrowdThroughOneFlowIsNotACoordinatedAttack(t *testing.T) {
	now := time.Now()
	var traces []*telemetry.TraceRecord
	// A quarter of the site's visitors arrive from one push notification: the
	// same app build on the same phone, so one User-Agent and one JA4, through
	// the promotion's three pages, every request served.
	const phone = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
	const phoneJA4 = "t13d2014h2_a09f3c656075_14788d8d241b"
	for i := range 25 {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		for j, path := range []string{"/promo/autumn", "/signup", "/thanks"} {
			traces = append(traces, &telemetry.TraceRecord{ServiceDelay: 1, SourceIP: ip, Path: path, Method: "GET",
				Status: "200", Timestamp: now.Add(time.Duration(j) * time.Second), UserAgent: phone, JA4: phoneJA4})
		}
	}
	// The other three quarters browse as a crowd does.
	for i := range 75 {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		for j, path := range []string{"/", fmt.Sprintf("/article/%d", i), "/about"} {
			traces = append(traces, &telemetry.TraceRecord{ServiceDelay: 1, SourceIP: ip, Path: path, Method: "GET",
				Status: "200", Timestamp: now.Add(time.Duration(j) * time.Second), UserAgent: fmt.Sprintf("UA-%d", i),
				JA4: fmt.Sprintf("t13d1516h2_%012d_0d2e82e5b8e9", i)})
		}
	}

	for _, a := range coordinatedFindings(t, traces) {
		t.Errorf("a crowd of readers was reported as a coordinated attack: %s", a.GetDescription())
	}
}

func TestVisitorsOfASinglePageAppAreNotACoordinatedAttack(t *testing.T) {
	now := time.Now()
	var traces []*telemetry.TraceRecord
	// Six visitors, each loading the application shell and its endpoints: the
	// same six paths, because that is what the application is.
	for i := range 6 {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		for j, path := range []string{"/app", "/assets/app.js", "/assets/app.css", "/api/me", "/api/feed", "/api/notifications"} {
			traces = append(traces, &telemetry.TraceRecord{ServiceDelay: 1, SourceIP: ip, Path: path, Method: "GET",
				Status: "200", Timestamp: now.Add(time.Duration(j) * time.Second), UserAgent: fmt.Sprintf("UA-%d", i),
				JA4: fmt.Sprintf("t13d1516h2_%012d_0d2e82e5b8e9", i)})
		}
	}

	for _, a := range coordinatedFindings(t, traces) {
		t.Errorf("six visitors of one application were reported as a coordinated attack: %s", a.GetDescription())
	}
}

// The guard must not cost the detection it guards: a scan spread over six
// addresses, each probing the same dozen paths that do not exist, is still
// one campaign, told by its failures.
func TestADistributedScanIsStillACoordinatedAttack(t *testing.T) {
	now := time.Now()
	var traces []*telemetry.TraceRecord
	for i := range 6 {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		for j := range 12 {
			traces = append(traces, &telemetry.TraceRecord{ServiceDelay: 1, SourceIP: ip, Path: fmt.Sprintf("/old/export-%d", j),
				Method: "GET", Status: "404", Timestamp: now.Add(time.Duration(j) * time.Second),
				UserAgent: "python-requests/2.32", JA4: "t13d1516h2_8c224e757c16_0d2e82e5b8e9"})
		}
	}

	if len(coordinatedFindings(t, traces)) == 0 {
		t.Fatal("a scan distributed over six addresses, every request failing, was not reported")
	}
}
