// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A fingerprint block is a client class on one network (ADR 0026). These pin
// what the operator's controls do with that: the Remove Mitigation the e2e suite
// and the threat views send (a bare fingerprint), the Allow on a row of the
// mitigation list (one block, exactly), and Add Mitigation.

const (
	blockScopeChrome      = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"
	blockScopeChromeNoRef = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cn0200_7e33b58890ac"
)

// Remove Mitigation with a threat's fingerprint -- how the dashboard's threat
// views and the Playwright suite release one -- releases every network the
// class is blocked on.
func TestRemovingAFingerprintReleasesItOnEveryNetwork(t *testing.T) {
	svc := newMitigationTestService(t)
	onA, onB := repid.For(blockScopeChrome, "203.0.113.7"), repid.For(blockScopeChrome, "198.51.100.7")
	telemetry.MarkUserMitigated(onA, "JA4+", "blocked", "waf")
	telemetry.MarkUserMitigated(onB, "JA4+", "blocked", "waf")

	// Named by another request of the same client: same class.
	res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: blockScopeChromeNoRef})
	if err != nil || !res.GetSuccess() {
		t.Fatalf("the release failed: err=%v %q", err, res.GetMessage())
	}
	if telemetry.IsUserMitigated(onA) || telemetry.IsUserMitigated(onB) {
		t.Errorf("after %q the class is still blocked (203.0.113: %v, 198.51.100: %v)", res.GetMessage(),
			telemetry.IsUserMitigated(onA), telemetry.IsUserMitigated(onB))
	}
}

// Allow on a row of the user mitigation list releases that row's block -- the
// class on that one network -- and not the class elsewhere.
func TestAllowOnAListedBlockReleasesOnlyThatNetwork(t *testing.T) {
	svc := newMitigationTestService(t)
	onA, onB := repid.For(blockScopeChrome, "203.0.113.7"), repid.For(blockScopeChrome, "198.51.100.7")
	telemetry.MarkUserMitigated(onA, "JA4+", "blocked", "waf")
	telemetry.MarkUserMitigated(onB, "JA4+", "blocked", "waf")

	list, err := svc.ListSecurityThreats(t.Context(), &gateonv1.ListSecurityThreatsRequest{Status: "userMitigated", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	var row *gateonv1.Anomaly
	for _, a := range list.GetThreats() {
		if a.GetSource() == onA {
			row = a
		}
	}
	if row == nil {
		t.Fatalf("the block on %s is not on the user mitigation list: %v", onA, list.GetThreats())
	}
	if row.GetJa4() != repid.Class(blockScopeChrome) {
		t.Errorf("the row names the class %q, want %q", row.GetJa4(), repid.Class(blockScopeChrome))
	}

	// What the dashboard's Allow sends for the row.
	res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{
		Source: row.GetSource(), Ja4Plus: row.GetJa4Plus(), Ja4H: row.GetJa4H(),
	})
	if err != nil || !res.GetSuccess() {
		t.Fatalf("Allow failed: err=%v %q", err, res.GetMessage())
	}
	if telemetry.IsUserMitigated(onA) {
		t.Error("the row's block survived its Allow")
	}
	if !telemetry.IsUserMitigated(onB) {
		t.Error("Allow on one network's block released the class on another network")
	}
}

// Add Mitigation with a bare fingerprint used to block that client build on
// every network. It now asks for the network, and blocks it there only.
func TestAddMitigationBlocksAFingerprintOnANetworkOnly(t *testing.T) {
	svc := newMitigationTestService(t)

	res, err := svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: blockScopeChrome})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetSuccess() {
		t.Fatalf("a bare fingerprint was blocked (%q); that blocks a browser build on every network", res.GetMessage())
	}
	if !strings.Contains(res.GetMessage(), "|203.0.113.7") {
		t.Errorf("the refusal does not say how to name a network: %q", res.GetMessage())
	}

	for _, source := range []string{blockScopeChrome + "|203.0.113.7", blockScopeChrome + "|203.0.113"} {
		res, err = svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: source})
		if err != nil || !res.GetSuccess() {
			t.Fatalf("%s: err=%v %q", source, err, res.GetMessage())
		}
	}
	if !telemetry.IsUserMitigated(repid.For(blockScopeChromeNoRef, "203.0.113.200")) {
		t.Error("the named network's clients of that build are not blocked")
	}
	if telemetry.IsUserMitigated(repid.For(blockScopeChrome, "198.51.100.7")) {
		t.Error("the block reached a network the operator did not name")
	}
}

// "Apply automatic fix" on a finding with a threat blocks the threat's address
// and nothing else. It used to block the class the threat came from on that
// address's network as well: every client of one browser build there, which
// is not the source the finding names (ADR 0063 decision 3, review-3 F2).
func TestTheBlockFixBlocksTheAddressNotTheThreatsClass(t *testing.T) {
	svc := newMitigationTestService(t)
	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
		ID: "scope-fix-1", Type: findingHighTraffic, SourceIP: "203.0.113.7", Fingerprint: blockScopeChrome,
		Score: 10, Category: "abuse", ActionTaken: telemetry.ActionDetected,
	})
	telemetry.FlushThreats()

	res, err := svc.ApplyRecommendation(t.Context(), &gateonv1.ApplyRecommendationRequest{
		AnomalyType: findingHighTraffic, Source: "203.0.113.7", ThreatId: "scope-fix-1",
	})
	if err != nil || !res.GetSuccess() {
		t.Fatalf("the fix failed: err=%v %q", err, res.GetMessage())
	}
	if !telemetry.IsIPMitigated("203.0.113.7") {
		t.Error("the threat's address is not blocked")
	}
	if telemetry.IsUserMitigated(repid.For(blockScopeChromeNoRef, "203.0.113.99")) {
		t.Error("the fix blocked the threat's client build on the threat's network")
	}
	if telemetry.IsUserMitigated(repid.For(blockScopeChrome, "198.51.100.7")) {
		t.Error("the fix blocked the threat's client build on a network the threat did not come from")
	}
}

// The "block" fix on a finding whose source is a fingerprint -- impossible
// travel reports one -- is refused rather than blocking the class everywhere.
func TestTheBlockFixRefusesABareFingerprint(t *testing.T) {
	svc := newMitigationTestService(t)
	res, err := svc.ApplyRecommendation(t.Context(), &gateonv1.ApplyRecommendationRequest{
		AnomalyType: findingHighTraffic, Source: blockScopeChrome,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetSuccess() {
		t.Fatalf("the fix blocked a bare fingerprint: %q", res.GetMessage())
	}
	for _, ip := range []string{"203.0.113.7", "198.51.100.7"} {
		if telemetry.IsUserMitigated(repid.For(blockScopeChrome, ip)) {
			t.Errorf("the refused fix blocked the build on %s", ip)
		}
	}
}
