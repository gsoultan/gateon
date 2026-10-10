// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ADR 0059: the analysis engine reads stored threats, and judged an address by
// all of them. These tests record threats the way the request path does,
// through the store, and hand the engine what detectAnomalies hands it.

// analysisStore gives the test a telemetry store of its own.
func analysisStore(t *testing.T) {
	t.Helper()
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "analysis.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
}

// recordN records n copies of th.
func recordN(n int, th telemetry.SecurityThreat) {
	for range n {
		th.Time = time.Now()
		telemetry.RecordSecurityThreat(th)
	}
}

// storedThreats is what detectAnomalies reads.
func storedThreats(t *testing.T) []*telemetry.SecurityThreat {
	t.Helper()
	telemetry.FlushThreats()
	return telemetry.GetSecurityThreatsLite(t.Context(), 1000, 0, nil)
}

func analysisEngine() *AnomalyAnalysisEngine {
	return NewAnomalyAnalysisEngine(&gateonv1.GlobalConfig{
		AnomalyDetection: &gateonv1.AnomalyDetectionConfig{SecurityThreatThreshold: 10},
	}, nil)
}

func findingFor(anomalies []*gateonv1.Anomaly, ip string) *gateonv1.Anomaly {
	for _, a := range anomalies {
		if a.GetSource() == ip {
			return a
		}
	}
	return nil
}

// TestTheAnalysisEngineJudgesAnAddressOnlyByWhatIsHeldAgainstIt: an address
// whose stored threats were detections the gateway let through, refusals of
// an earlier shun and policy refusals was reported as a WAF violator -- each
// refusal a "WAF hit" worth 40, each detection a warning worth 5 -- and the
// observed matches were attack evidence once read back, because the store did
// not keep that they were observed. An address the WAF refused three times on
// attack payloads still is reported.
func TestTheAnalysisEngineJudgesAnAddressOnlyByWhatIsHeldAgainstIt(t *testing.T) {
	analysisStore(t)
	const innocent, attacker, scanner = "100.64.70.10", "100.64.71.10", "100.64.73.10"
	// An audit-only WAF's fast-path matches: the type an enforcing WAF
	// refuses with, recorded observed.
	recordN(40, telemetry.SecurityThreat{Type: "fast_path_signature", SourceIP: innocent, Score: 100,
		Category: "waf", ActionTaken: telemetry.ActionDetected, Observed: true})
	recordN(20, telemetry.SecurityThreat{Type: "ip_mitigation", SourceIP: innocent, Score: 100,
		Category: "advanced", ActionTaken: telemetry.ActionBlocked})
	recordN(10, telemetry.SecurityThreat{Type: "geoip_block", SourceIP: innocent, Score: 50,
		Category: "geofencing", ActionTaken: telemetry.ActionBlocked})
	recordN(3, telemetry.SecurityThreat{Type: "waf_blocked", SourceIP: attacker, Score: 100,
		Category: "waf", ActionTaken: telemetry.ActionBlocked, TriggeredRules: "[942100]"})

	// Exploit-scan detections the anomaly detector could only flag, from an
	// address shunned since: read back, the shun makes them "mitigated".
	recordN(2, telemetry.SecurityThreat{Type: "exploit_scan", SourceIP: scanner, Score: 60,
		Category: "exploit_scanning", ActionTaken: telemetry.ActionFlagged})
	if err := telemetry.MarkIPMitigated(scanner, "test: shunned since"); err != nil {
		t.Fatal(err)
	}

	data := &DiagnosticData{SecurityThreats: storedThreats(t)}
	anomalies := analysisEngine().Analyze(t.Context(), data)

	if st := data.IPStats[innocent]; st != nil && (st.WAFHits != 0 || st.WAFWarnings != 0 || st.AttackEvidence != 0) {
		t.Errorf("the innocent address was counted %d WAF hits, %d warnings, attack evidence %v",
			st.WAFHits, st.WAFWarnings, st.AttackEvidence)
	}
	if a := findingFor(anomalies, innocent); a != nil {
		t.Errorf("the innocent address was reported: %s", a.GetDescription())
	}
	st := data.IPStats[attacker]
	if st == nil || st.WAFHits != 3 || st.AttackEvidence != 3 {
		t.Fatalf("the attacker's three WAF refusals were counted as %+v", st)
	}
	if findingFor(anomalies, attacker) == nil {
		t.Error("the attacker the WAF refused three times was not reported")
	}
	if sc := data.IPStats[scanner]; sc == nil || sc.WAFHits != 0 || sc.WAFWarnings != 2 {
		t.Errorf("two flagged detections from an address shunned since were counted as %+v, "+
			"want two warnings: nothing refused them when they were recorded", sc)
	}
}

// TestTheAnalysisEngineCountsAPasswordTheGatewayRefused: since ADR 0059 the
// gateway's authentication marks its refusals, and the trace carries the
// mark. A refusal mark used to mean "not a credential attempt" to the trace
// side, so a password guessed against Basic auth would have stopped counting.
func TestTheAnalysisEngineCountsAPasswordTheGatewayRefused(t *testing.T) {
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(t.TempDir(), "traces"))
	analysisStore(t)
	const guesser = "100.64.74.10"
	h := middleware.Metrics("basic-route")(middleware.BasicAuth("admin", "right-password")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	for range 3 {
		req := httptest.NewRequest(http.MethodGet, "/reports", nil)
		req.RemoteAddr = guesser + ":51000"
		req.SetBasicAuth("admin", "a-guess")
		req = req.WithContext(request.WithState(req.Context(), &request.RequestState{RequestID: request.GenerateID()}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("a wrong password got %d", rr.Code)
		}
	}
	telemetry.FlushTraces()
	data := &DiagnosticData{Traces: telemetry.GetTracesFiltered(t.Context(), 100, true)}
	analysisEngine().Analyze(t.Context(), data)
	if st := data.IPStats[guesser]; st == nil || st.CredentialFailures != 3 {
		t.Fatalf("three passwords Basic auth refused were counted as %+v credential failures", st)
	}
}

// TestTheAnalysisEnginesFindingIsNotHeldAgainstTheAddress: the engine records
// its finding about an address on every pass. Held against the address, each
// pass took half its score off the reputation again for the same requests --
// which the WAF had already counted, once, when it refused them.
func TestTheAnalysisEnginesFindingIsNotHeldAgainstTheAddress(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	analysisStore(t)
	const (
		attacker = "100.64.72.10"
		build    = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"
	)
	id := repid.For(build, attacker)
	t.Cleanup(func() { telemetry.ResetReputation(id) })
	recordN(3, telemetry.SecurityThreat{Type: "waf_blocked", SourceIP: attacker, Score: 100,
		Category: "waf", ActionTaken: telemetry.ActionBlocked})
	traces := []*telemetry.TraceRecord{{ServiceDelay: 1, SourceIP: attacker, Fingerprint: build, Path: "/search",
		Method: "GET", Status: "403 Forbidden", Timestamp: time.Now()}}

	for pass := range 3 {
		data := &DiagnosticData{SecurityThreats: storedThreats(t), Traces: traces}
		if findingFor(analysisEngine().Analyze(t.Context(), data), attacker) == nil {
			t.Fatalf("pass %d did not report the attacker, so the assertions below prove nothing", pass+1)
		}
		telemetry.FlushThreats()
		if got := telemetry.GetReputationScore(id); got != 100 {
			t.Fatalf("after pass %d the engine's own finding had moved the score to %v", pass+1, got)
		}
	}
	for _, th := range storedThreats(t) {
		if th.SourceIP == attacker && th.Type != "waf_blocked" && th.HeldAgainstSource() {
			t.Errorf("the engine's finding %s is stored held against its source", th.Type)
		}
	}
}
