// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// ADR 0059: a request the gateway let through is not evidence against its
// client. These are the detection-only paths that live in this package.

// subscribeThreats returns a subscription to every threat recorded.
func subscribeThreats(t *testing.T) chan SecurityThreat {
	t.Helper()
	ch := ThreatBroadcaster.Subscribe()
	t.Cleanup(func() { ThreatBroadcaster.Unsubscribe(ch) })
	return ch
}

// observedOnly fails the test when nothing was recorded, or when anything
// recorded is held against its source.
func observedOnly(t *testing.T, ch chan SecurityThreat) {
	t.Helper()
	if len(ch) == 0 {
		t.Fatal("nothing was recorded, so the assertions above prove nothing")
	}
	for len(ch) > 0 {
		if th := <-ch; th.HeldAgainstSource() {
			t.Errorf("%s (action %q) is held against its source", th.Type, th.ActionTaken)
		}
	}
}

// TestBehaviouralProfilingNeverLowersTheClientsReputation: profiling runs on a
// request already answered, and each finding -- a probe-looking path, a run of
// 404s, a steady rhythm -- took half its score off the client's reputation.
// A client that followed three stale links to /.env/... was refused by the
// reputation blocker on every route.
func TestBehaviouralProfilingNeverLowersTheClientsReputation(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	freshStore(t)
	threats := subscribeThreats(t)
	const client = "100.64.20.10"
	id := repid.For(allowlistedBuild, client)
	t.Cleanup(func() { ResetReputation(id) })

	for range 6 {
		r := httptest.NewRequest(http.MethodGet, "/.env/backup", nil)
		r.RemoteAddr = client + ":40000"
		r = r.WithContext(request.WithState(r.Context(), &request.RequestState{JA4Plus: allowlistedBuild}))
		TrackBehavior(allowlistedBuild, r, http.StatusNotFound)
		FlushThreats()
	}
	if got := GetReputationScore(id); got != 100 {
		t.Errorf("behavioural findings moved the client's score to %v", got)
	}
	observedOnly(t, threats)
}

// TestADevicePostureChangeIsNotHeldAgainstTheNewDevice: a user whose browser
// updated, or who signed in from a second device, presents a new fingerprint.
// The change is recorded and the request goes on; it was held against the new
// fingerprint as if it had been refused.
func TestADevicePostureChangeIsNotHeldAgainstTheNewDevice(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	freshStore(t)
	threats := subscribeThreats(t)
	const (
		oldDevice = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_0000000000a1"
		newDevice = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_0000000000b2"
		user      = "posture-user"
		client    = "100.64.21.10"
	)
	id := repid.For(newDevice, "")
	t.Cleanup(func() { ResetReputation(id); userLocationCache.Remove(user) })
	r := httptest.NewRequest(http.MethodGet, "/account", nil)

	for _, fp := range []string{oldDevice, newDevice, oldDevice, newDevice} {
		if err := CheckZeroTrust(user, fp, client, r); err != nil {
			t.Fatalf("a fingerprint change was refused: %v", err)
		}
		FlushThreats()
	}
	if got := GetReputationScore(id); got != 100 {
		t.Errorf("a device posture change moved the new device's score to %v", got)
	}
	observedOnly(t, threats)
}

// TestAThreatNotHeldAgainstItsSourceAddsNothingToItsAddressScore: the
// per-address score the alerting manager's autonomous shun reads summed every
// threat, the ones held against nobody included.
func TestAThreatNotHeldAgainstItsSourceAddsNothingToItsAddressScore(t *testing.T) {
	freshStore(t)
	const client = "100.64.22.10"
	RecordSecurityThreat(SecurityThreat{Type: "xss_detected", SourceIP: client, Score: 90,
		ActionTaken: ActionDetected, Observed: true})
	FlushThreats()
	if got := GetIPThreatScore(client); got != 0 {
		t.Fatalf("an observed detection added %v to its address's threat score", got)
	}
	RecordSecurityThreat(SecurityThreat{Type: "waf_blocked", SourceIP: client, Score: 90, ActionTaken: ActionBlocked})
	FlushThreats()
	if got := GetIPThreatScore(client); got != 90 {
		t.Fatalf("a WAF refusal left its address's threat score at %v, want 90", got)
	}
}

// TestNothingNotHeldAgainstItsSourceIsAttackEvidence: the analysis engine and
// Graph Intelligence weigh stored threats with AttackEvidenceWeight. An
// audit-only WAF's fast-path match is recorded observed under the type an
// enforcing one refuses with, and was weighed as a refusal.
func TestNothingNotHeldAgainstItsSourceIsAttackEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		th   SecurityThreat
		want float64
	}{
		{"an enforcing fast-path refusal", SecurityThreat{Type: threatFastPathSignature, ActionTaken: ActionBlocked}, 1},
		{"an audit-only fast-path match", SecurityThreat{Type: threatFastPathSignature, ActionTaken: ActionDetected, Observed: true}, 0},
		{"a trap sprung", SecurityThreat{Type: threatHoneypotTriggered}, DecisiveAttackWeight},
		{"a cross-site trap load", SecurityThreat{Type: threatHoneypotTriggered, Unattributed: true}, 0},
	} {
		if got := AttackEvidenceWeight(&tc.th); got != tc.want {
			t.Errorf("%s: AttackEvidenceWeight = %v, want %v", tc.name, got, tc.want)
		}
	}
}
