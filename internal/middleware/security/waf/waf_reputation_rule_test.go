// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The WAF's reputation rules -- 1910001, an address a feed lists, and 1910002,
// a client whose own score fell below 20 -- refuse on a decision the gateway
// already made. Each refusal was recorded as a waf_blocked held against the
// client: it took 50 more off the score, counted as attack evidence, and fed
// the exploit-scan tally. The third retry blocked the client's browser build on
// its whole /24, so every bystander there with the same build was refused on
// every route (review 3, F1). ADR 0055 says a refusal of an earlier decision is
// not new evidence; these tests hold the WAF's to that.

// reputationRuleRoute is a route WAF with its reputation rules on, behind the
// fingerprint block every route carries, over a telemetry store of its own.
func reputationRuleRoute(t *testing.T, feed *reputation.IPReputationStore) (http.Handler, chan telemetry.SecurityThreat) {
	t.Helper()
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "rep-rule.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	telemetry.ResetFingerprintSightings()
	t.Cleanup(telemetry.ResetFingerprintSightings)
	threats := telemetry.ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { telemetry.ThreatBroadcaster.Unsubscribe(threats) })

	mw, err := WAF(WAFConfig{ParanoiaLevel: 1, EnableIPReputation: true, RouteID: t.Name(), Reputation: feed})
	if err != nil {
		t.Fatalf("build WAF: %v", err)
	}
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return identity.UserMitigation()(mw(origin)), threats
}

// visitScored sends one ordinary POST from ip with stockBuild, carrying the
// reputation the reputation blocker in front of the WAF would have cached on
// the request state, and returns what the client got and the state.
func visitScored(t *testing.T, h http.Handler, ip string, score float64) (*httptest.ResponseRecorder, *request.RequestState) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/account", strings.NewReader(`{"name":"ada"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":40000"
	rs := &request.RequestState{JA4Plus: stockBuild, Reputation: score}
	req = req.WithContext(request.WithState(req.Context(), rs))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	telemetry.FlushThreats()
	return rr, rs
}

// wafBlocksFor is the per-address WAF-block tally the exploit-scan detector
// shuns on.
func wafBlocksFor(ip string) float64 {
	for _, s := range telemetry.GetAggregator().GetIPStats(0) {
		if s.IP == ip {
			return s.WafBlocks
		}
	}
	return 0
}

// assertRefusalOfEarlierDecision drives four refusals by rule from client and
// checks none of them counted against it, and that a bystander on the same /24
// with the same build is still served.
func assertRefusalOfEarlierDecision(t *testing.T, h http.Handler, threats chan telemetry.SecurityThreat,
	client, bystander string, score float64, rule string) {
	t.Helper()
	key := repid.For(stockBuild, client)
	t.Cleanup(func() { telemetry.ResetReputation(key) })
	before := telemetry.GetReputationScore(key)

	for i := range 4 {
		rr, rs := visitScored(t, h, client, score)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("refusal %d got %d (%q), want the WAF's 403", i+1, rr.Code, rr.Body.String())
		}
		if rs.Refused != request.RefusalMitigation {
			t.Errorf("refusal %d is marked %q, want %q: it checked no credential (ADR 0031)",
				i+1, rs.Refused, request.RefusalMitigation)
		}
	}
	assertRecordedNotHeld(t, recorded(threats), rule)

	if got := telemetry.GetReputationScore(key); got != before {
		t.Errorf("the refusals moved the client's score from %v to %v", before, got)
	}
	if got := wafBlocksFor(client); got != 0 {
		t.Errorf("the refusals added %v to the exploit-scan tally", got)
	}
	if telemetry.IsUserMitigated(key) {
		t.Errorf("the refusals blocked the client's build on its network (%s)", key)
	}
	if rr, _ := visitScored(t, h, bystander, 100); rr.Code != http.StatusOK {
		t.Errorf("a bystander on the client's network with the same build got %d (%q)", rr.Code, rr.Body.String())
	}
}

// assertRecordedNotHeld checks every refusal was recorded -- so the assertions
// above are not passing because nothing was -- and none is held against its
// source or is attack evidence.
func assertRecordedNotHeld(t *testing.T, threats []telemetry.SecurityThreat, rule string) {
	t.Helper()
	var refusals int
	for i := range threats {
		th := &threats[i]
		if !strings.Contains(th.TriggeredRules, rule) {
			continue
		}
		refusals++
		if th.HeldAgainstSource() || telemetry.AttackEvidenceWeight(th) != 0 || !th.Mitigated {
			t.Errorf("rule %s refusal recorded as %s held=%v evidence=%v mitigated=%v",
				rule, th.Type, th.HeldAgainstSource(), telemetry.AttackEvidenceWeight(th), th.Mitigated)
		}
	}
	if refusals != 4 {
		t.Fatalf("%d refusals by rule %s were recorded, want 4 (%d threats)", refusals, rule, len(threats))
	}
}

// TestTheWAFReputationRuleDoesNotHoldItsRefusalAgainstTheClient is rule
// 1910002: a client whose score fell below 20 keeps being refused, and its
// refusals no longer push it, or its network, further.
func TestTheWAFReputationRuleDoesNotHoldItsRefusalAgainstTheClient(t *testing.T) {
	h, threats := reputationRuleRoute(t, nil)
	assertRefusalOfEarlierDecision(t, h, threats, "198.51.100.9", "198.51.100.200", 5, "1910002")
}

// TestTheWAFFeedRuleDoesNotHoldItsRefusalAgainstTheClient is rule 1910001: a
// feed listing is never evidence towards an escalation (ADR 0044).
func TestTheWAFFeedRuleDoesNotHoldItsRefusalAgainstTheClient(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "203.0.113.70")
	}))
	t.Cleanup(feed.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	store := reputation.NewIPReputationStore(&gateonv1.IPReputationConfig{Enabled: true, FeedUrls: []string{feed.URL}})
	store.Start(ctx) // the first load is synchronous

	h, threats := reputationRuleRoute(t, store)
	assertRefusalOfEarlierDecision(t, h, threats, "203.0.113.70", "203.0.113.71", 100, "1910001")
}
