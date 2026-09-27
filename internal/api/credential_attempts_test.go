// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The per-IP detector's brute-force check counted every 401 and 403 an address
// was answered with. A dashboard tab left open after its session expired keeps
// polling, every poll is a GET answered 401, and within minutes the tab was
// filed as a brute-force attacker -- a threat whose score also costs the
// client reputation.
//
// These tests record traces the way the metrics middleware does, with the
// request's real header map, and analyse the summary traces the analysis pass
// reads, so the flag the recording path derives from the Authorization header
// is exercised end to end.

// tracedRequest is one client's request, recorded n times by recordRequests;
// header returns the i-th request's headers.
type tracedRequest struct {
	ip, method, path, status string
	header                   func(i int) map[string][]string
}

// sameHeaders is the header function of a client that sends the same headers
// every time.
func sameHeaders(h map[string][]string) func(int) map[string][]string {
	return func(int) map[string][]string { return h }
}

// recordRequests records n traces of req, every apart from start.
func recordRequests(t *testing.T, req tracedRequest, n int, every time.Duration, start time.Time) {
	t.Helper()
	for i := range n {
		telemetry.RecordTrace(fmt.Sprintf("%s-%s-%d", req.ip, req.path, i), req.method+" "+req.path,
			"rt-app", "svc-app", 4, start.Add(time.Duration(i)*every), req.status, req.path, req.ip, "", "",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", req.method, "", "app.example.com"+req.path, "", "",
			req.header(i), nil, "", 100, 0, 0, 0, 0)
	}
}

// findingsAbout runs the production analysis pass -- the engine as the default
// configuration builds it -- over the recorded summary traces and returns what
// it reports about ip.
func findingsAbout(t *testing.T, ip string) []*gateonv1.Anomaly {
	t.Helper()
	telemetry.FlushTraces()
	engine := NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{Sensitivity: 0.5, CheckIntervalSeconds: 60},
	}, nil)
	var out []*gateonv1.Anomaly
	for _, a := range engine.Analyze(t.Context(), &DiagnosticData{Traces: analysisTraces(t.Context())}) {
		if a.GetSource() == ip {
			out = append(out, a)
		}
	}
	return out
}

func describe(anomalies []*gateonv1.Anomaly) string {
	s := ""
	for _, a := range anomalies {
		s += fmt.Sprintf("\n  %s (score %.0f): %s", a.GetType(), a.GetScore(), a.GetDescription())
	}
	return s
}

// dashboardPolls are what an open dashboard tab asks for every five seconds.
var dashboardPolls = []string{"/api/notifications", "/api/metrics", "/api/status", "/api/alerts"}

// A tab whose session expired polls four endpoints every five seconds, and for
// three minutes every poll comes back 401. It is guessing nothing: it presents
// the one session it had, in a cookie, and a GET carries no credential.
func TestExpiredSessionTabIsNotReportedAsBruteForce(t *testing.T) {
	openTraceStore(t)
	start := time.Now().Add(-4 * time.Minute)
	cookie := sameHeaders(map[string][]string{"Cookie": {"session=expired"}, "Accept": {"application/json"}})
	for i, path := range dashboardPolls {
		recordRequests(t, tracedRequest{ip: "203.0.113.30", method: http.MethodGet, path: path, status: "401", header: cookie},
			36, 5*time.Second, start.Add(time.Duration(i)*time.Second))
	}

	if found := findingsAbout(t, "203.0.113.30"); len(found) > 0 {
		t.Errorf("an expired-session tab polling with GETs was reported:%s", describe(found))
	}
}

// The same tab in an application that keeps its token in an Authorization
// header rather than a cookie: every poll re-presents the one bearer token the
// server issued and has since expired. A token the server minted is not a
// guess, however often it is repeated.
func TestStaleBearerTokenIsNotReportedAsBruteForce(t *testing.T) {
	openTraceStore(t)
	start := time.Now().Add(-4 * time.Minute)
	bearer := sameHeaders(map[string][]string{"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.e30.expired"}})
	for i, path := range dashboardPolls {
		recordRequests(t, tracedRequest{ip: "203.0.113.31", method: http.MethodGet, path: path, status: "401", header: bearer},
			36, 5*time.Second, start.Add(time.Duration(i)*time.Second))
	}

	if found := findingsAbout(t, "203.0.113.31"); len(found) > 0 {
		t.Errorf("a client re-presenting one expired bearer token was reported:%s", describe(found))
	}
}

// Credential stuffing: one address POSTing to the login form, refused every
// time. This is what the check exists for, and it must survive the change.
func TestCredentialStuffingIsReportedAsBruteForce(t *testing.T) {
	openTraceStore(t)
	form := sameHeaders(map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}})
	recordRequests(t, tracedRequest{ip: "203.0.113.32", method: http.MethodPost, path: "/login", status: "401", header: form},
		30, 2*time.Second, time.Now().Add(-2*time.Minute))

	assertBruteForceReported(t, "203.0.113.32")
}

// HTTP Basic guessing is a GET too: the password travels in the Authorization
// header, not a form. The recording path flags a request that presents one
// (TraceRecord.PasswordAuth), because the summary traces the analysis reads
// carry no headers; without the flag this attack would weigh no more than the
// expired tab above, and it keeps exactly the weight it had before GETs
// stopped counting.
func TestHTTPBasicGuessingOverGETIsReportedAsBruteForce(t *testing.T) {
	openTraceStore(t)
	guesses := func(i int) map[string][]string {
		return map[string][]string{"Authorization": {fmt.Sprintf("Basic YWRtaW46Z3Vlc3M%04d", i)}}
	}
	recordRequests(t, tracedRequest{ip: "203.0.113.33", method: http.MethodGet, path: "/internal/reports", status: "401", header: guesses},
		120, 2*time.Second, time.Now().Add(-5*time.Minute))

	assertBruteForceReported(t, "203.0.113.33")
}

func assertBruteForceReported(t *testing.T, ip string) {
	t.Helper()
	found := findingsAbout(t, ip)
	for _, a := range found {
		if a.GetType() == findingBruteForce {
			return
		}
	}
	t.Errorf("no %s finding for %s; reported:%s", findingBruteForce, ip, describe(found))
}
