// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The gaps between a client's requests feed the request-timing check and two
// of the Neural Sentinel's features. Every gap was dead in production, and the
// check they fed, once alive, reported every poller as a threat. Found by the
// 2026-09-27 AI-analysis review as open findings; fixed with them.

const regularIntervals = "regular request intervals"

// TestRequestTimingReachesTheDetectorFromStoredTraces: a client on a fixed
// 2-second timer, recorded and read back the way the analysis pass reads it.
// The store returns its newest trace first, and the engine measured each gap
// as this trace minus the one before, keeping only positive gaps -- so every
// gap was dropped, and no client ever had an interval measured.
//
// The open version of this test passed on a "regular request intervals"
// finding for this client. That is the finding the next test forbids: a
// client on a timer is not a threat. What this test asks for is the input.
func TestRequestTimingReachesTheDetectorFromStoredTraces(t *testing.T) {
	openTraceStore(t)
	const poller = "10.44.0.7"
	recordPolling(poller, "/api/items", 2*time.Second, 30)
	telemetry.FlushTraces()

	data := &DiagnosticData{Traces: analysisTraces(t.Context())}
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	st := data.IPStats[poller]
	if st == nil {
		t.Fatalf("the poller's traces did not come back from the store")
	}
	if st.IATCount != 29 {
		t.Fatalf("30 requests on a fixed 2s timer were read back from the store and %d inter-arrival "+
			"intervals were measured, want 29", st.IATCount)
	}
	if mean := st.IATSum / float64(st.IATCount); math.Abs(mean-2000) > 1 {
		t.Errorf("the measured gaps average %.0fms, want 2000ms", mean)
	}
}

// TestSimultaneousRequestsAreGapsToo: a browser fetches a page's assets at
// once. Dropping the zero gaps left only the pauses between pages, which is a
// steadier rhythm than the client ever kept.
func TestSimultaneousRequestsAreGapsToo(t *testing.T) {
	const ip = "10.44.0.12"
	at := time.Now().Add(-time.Minute)
	data := &DiagnosticData{Traces: []*telemetry.TraceRecord{
		trace(ip, "/", "200", 10, at), trace(ip, "/app.js", "200", 5, at), trace(ip, "/next", "200", 10, at.Add(time.Second)),
	}}
	NewAnomalyAnalysisEngine(nil, nil).Analyze(t.Context(), data)
	if st := data.IPStats[ip]; st.IATCount != 2 || st.IATSum != 1000 {
		t.Errorf("three requests, two of them simultaneous: %d gaps summing to %.0fms, want 2 summing to 1000ms",
			st.IATCount, st.IATSum)
	}
}

// TestPollersAreNotThreats: a dashboard page polling its status endpoint every
// five seconds, a health checker, a CI job and a tab whose session expired and
// keeps polling into 401s. "CV < 0.05" was worth 60 points on its own, twice
// the default threat threshold, so once the gaps were measured each was filed
// as a security threat on every pass -- on a quiet site outright, and on a
// busier one wherever its other traffic added a few points.
func TestPollersAreNotThreats(t *testing.T) {
	pollers := []struct {
		who, ip string
		add     func(tf *traffic, ip string)
	}{
		{"dashboard polling every 5s", "10.46.0.1", func(tf *traffic, ip string) { tf.poller(ip, "/api/status", 5*time.Second, 40) }},
		{"health checker every 10s", "10.46.0.2", func(tf *traffic, ip string) { tf.poller(ip, "/healthz", 10*time.Second, 60) }},
		{"CI job", "10.46.0.3", func(tf *traffic, ip string) { tf.ciRunner(ip) }},
		{"tab with an expired session, polling every 5s", "10.46.0.4", func(tf *traffic, ip string) {
			tf.expiredSessionPoller(ip, "/api/status", 5*time.Second, 120)
		}},
	}
	for _, crowd := range []int{0, 30} {
		for _, p := range pollers {
			t.Run(fmt.Sprintf("%s among %d browsers", p.who, crowd), func(t *testing.T) {
				tf := newTraffic(11, time.Now().Add(-10*time.Minute))
				tf.browsers("10.45", crowd)
				p.add(tf, p.ip)
				data := tf.data()
				for _, a := range behavioralEngine().Analyze(t.Context(), data) {
					if a.GetSource() == p.ip && strings.Contains(a.GetDescription(), regularIntervals) {
						t.Errorf("%s was reported: %s (score %.0f)", p.who, a.GetDescription(), a.GetScore())
					}
				}
				// The check had its input and declined: without this, a
				// regression that stopped measuring gaps again would pass.
				if st := data.IPStats[p.ip]; st == nil || st.IATCount < 39 {
					t.Fatalf("the %s's gaps were not measured: %+v", p.who, st)
				}
			})
		}
	}
}

// TestRegularTimingStillCountsOnHarmfulTraffic: a credential-stuffing script
// keeps a machine's rhythm on requests that are failing, and that still counts.
func TestRegularTimingStillCountsOnHarmfulTraffic(t *testing.T) {
	const stuffer = "10.47.0.9"
	tf := newTraffic(12, time.Now().Add(-10*time.Minute))
	tf.browsers("10.48", 20)
	tf.credentialStuffer(stuffer, 100)

	for _, a := range behavioralEngine().Analyze(t.Context(), tf.data()) {
		if a.GetSource() == stuffer && strings.Contains(a.GetDescription(), regularIntervals) {
			return
		}
	}
	t.Errorf("a script POSTing /login every 600ms into 401s kept a machine's rhythm and the timing check did not say so")
}

// TestASampledOfficeEgressIsNotAScan: under GATEON_TRACE_SAMPLE_RATE=20 the
// store keeps every failure and one success in twenty. Read as if it were
// everything, an address with a 5% failure rate spread over its pages fails
// half the time -- the shape of a scan.
func TestASampledOfficeEgressIsNotAScan(t *testing.T) {
	st := newIPStats("")
	st.TotalRequests = 60 // 30 sampled successes stand for 600
	st.Error404 = 30
	st.FailedPaths = map[string]int{}
	for p := range 30 {
		st.FailedPaths[fmt.Sprintf("/page-%d", p)] = 1
	}
	if harm, ok := st.harmEvidence(20); ok {
		t.Errorf("30 missing pages among ~630 requests, read off a 1-in-20 sample, were judged harmful: %s", harm)
	}
	if _, ok := st.harmEvidence(1); !ok {
		t.Fatalf("precondition: unsampled, 30 failures across 30 paths out of 60 requests should look like a scan")
	}
}

// behavioralEngine is the engine with per-address behavioural analysis on, as
// an operator who enables it runs it.
func behavioralEngine() *AnomalyAnalysisEngine {
	return NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		SecurityAdvanced: &gateonv1.SecurityAdvancedConfig{Behavioral: &gateonv1.BehavioralConfig{Enabled: true}},
	}, nil)
}

// recordPolling records n successful requests from ip to path, gap apart,
// ending a minute ago.
func recordPolling(ip, path string, gap time.Duration, n int) {
	start := time.Now().Add(-time.Minute - time.Duration(n)*gap)
	for i := range n {
		telemetry.RecordTrace(fmt.Sprintf("poll-%s-%02d", ip, i), "GET "+path, "rt-poll", "svc-poll",
			12, start.Add(time.Duration(i)*gap), "200", path, ip, "", "", "poller/1.0",
			http.MethodGet, "", path, "", "", nil, nil, "", 100, 0, 0, 0, 0)
	}
}

func trace(ip, path, status string, ms float64, at time.Time) *telemetry.TraceRecord {
	return &telemetry.TraceRecord{
		SourceIP: ip, Path: path, Method: http.MethodGet, Status: status, DurationMs: ms,
		Timestamp: at, UserAgent: "Mozilla/5.0",
	}
}
