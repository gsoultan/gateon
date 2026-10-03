// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/correlation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// stockChrome is one browser build: every user of it presents this JA4+.
const stockChrome = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"

// TestABystanderIsNotRefusedForAnotherNetworksAttack is TRUTH-NEW-1 through
// the real recording path, correlation engine and responder (ADR 0055).
//
// One false positive against a user on 203.0.113.0/24 and an attacker's blocks
// and trap hit on 198.18.5.0/24, all from the same browser build. Grouped by
// build, the four made one incident with two signal types, the responder
// restricted every participant's network, and a bystander on the user's /24
// who sent nothing was refused on every route.
func TestABystanderIsNotRefusedForAnotherNetworksAttack(t *testing.T) {
	const victim, bystander, attacker = "203.0.113.10", "203.0.113.11", "198.18.5.5"
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "bystander.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	for _, ip := range []string{victim, attacker} {
		id := repid.For(stockChrome, ip)
		t.Cleanup(func() { telemetry.ResetReputation(id) })
	}

	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })
	signals := make(chan correlation.Signal, 16)
	sinks := threatSinks{signals: signals, correlate: true}
	mitigator := initMitigator()
	engine := correlation.New(correlation.Config{OnIncident: func(inc correlation.Incident) { mitigator.Handle(inc) }})

	record := func(ip, typ, category string) {
		telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
			Type: typ, Category: category, SourceIP: ip, Fingerprint: stockChrome,
			Score: 100, Severity: "high", ActionTaken: telemetry.ActionBlocked,
		})
		telemetry.FlushThreats()
		for len(threats) > 0 {
			th := <-threats
			sinks.forward(&th)
		}
		for len(signals) > 0 {
			engine.Observe(<-signals)
		}
	}
	record(victim, "waf_blocked", "xss")
	record(attacker, "honeypot_triggered", "deception")
	record(attacker, "waf_blocked", "sqli")
	record(attacker, "waf_blocked", "sqli")

	if code := throughTheReputationBlocker(bystander); code != http.StatusOK {
		t.Errorf("a client on %s/24 that sent nothing got %d: another network's attack, sharing only a "+
			"browser build, was held against its network", victim, code)
	}
	if got := telemetry.GetReputationScore(repid.For(stockChrome, attacker)); got >= 2 {
		t.Errorf("the attacker's own network scores %v for the build; the incident on it was not acted on, "+
			"so the assertion above proves nothing", got)
	}
}

// TestARefusalOfAnEarlierDecisionIsNotASignal: a feed listing's refusal is
// "never evidence towards an escalation" (ADR 0044), yet every refusal it made
// was a correlation signal, as was every refusal of a shun, a fingerprint block
// or a low score. A listed address that only ever got refused turned up as a
// correlated incident (signal_types=ip_mitigation,...), and a client refused by
// the reputation blocker fed the incident that would refuse it further.
func TestARefusalOfAnEarlierDecisionIsNotASignal(t *testing.T) {
	signals := make(chan correlation.Signal, 8)
	sinks := threatSinks{signals: signals, correlate: true}

	for _, typ := range []string{"ip_mitigation", "user_mitigation", "ip_shunning", "reputation_block"} {
		sinks.forward(&telemetry.SecurityThreat{
			Type: typ, SourceIP: "192.0.2.66", Fingerprint: stockChrome, ActionTaken: telemetry.ActionBlocked,
		})
	}
	if got := len(signals); got != 0 {
		t.Fatalf("%d refusals of earlier decisions reached the correlation engine, want 0: %v", got, (<-signals).Type)
	}

	sinks.forward(&telemetry.SecurityThreat{
		Type: "waf_blocked", SourceIP: "192.0.2.66", Fingerprint: stockChrome, ActionTaken: telemetry.ActionBlocked,
	})
	if got := len(signals); got != 1 {
		t.Fatalf("a WAF refusal of what the client sent was not correlated (%d signals)", got)
	}
}

// TestAnObservedMatchIsNotASignal: an audit-only WAF "blocks nothing", and its
// matches fed the incidents whose response restricted the client (ADR 0055).
func TestAnObservedMatchIsNotASignal(t *testing.T) {
	signals := make(chan correlation.Signal, 2)
	sinks := threatSinks{signals: signals, correlate: true}

	sinks.forward(&telemetry.SecurityThreat{
		Type: "waf_detected", SourceIP: "203.0.113.70", Fingerprint: stockChrome, Observed: true,
	})
	if got := len(signals); got != 0 {
		t.Fatalf("an audit-only match reached the correlation engine")
	}
}

// throughTheReputationBlocker sends a request from ip, with stockChrome, through
// the blocker every route carries, and returns the status.
func throughTheReputationBlocker(ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/home", nil)
	req.RemoteAddr = ip + ":40000"
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: stockChrome}))
	rr := httptest.NewRecorder()
	identity.ReputationBlocker("bystander-route")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rr, req)
	return rr.Code
}
