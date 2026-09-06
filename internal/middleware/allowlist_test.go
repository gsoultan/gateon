// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// GATEON_MITIGATION_ALLOWLIST is documented as a "CIDR/IP list never mitigated".
// Exactly one thing honoured it: the Responder, which handles correlated
// incidents after the fact. Every synchronous way gateon mitigates ignored it.
//
// So an operator who allowlisted their office egress, their monitoring vendor or
// their own security team's scanner was still refused by the reputation blocker,
// still banned by the honeypot, still delayed by the tarpit and still challenged
// by proof-of-work. The setting did not do the one thing its name promises, and
// it failed in the worst direction: it looks like it worked until someone is
// locked out.
//
// Root cause in one sentence: the allowlist was a field on one component instead
// of a property of the deployment.

// withAllowlist installs an allowlist for the duration of a test.
func withAllowlist(t *testing.T, cidrs string) {
	t.Helper()
	mitigation.SetAllowlist(mitigation.ParseAllowlist(cidrs))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
}

// TestAllowlistedSourceIsNotRefusedByReputation covers the 403.
func TestAllowlistedSourceIsNotRefusedByReputation(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658_allowlist"
	client := repTestClient{ja4Plus: browser, remoteIP: "203.0.113.90"}

	// Earn a score of zero the way the threat pipeline would.
	telemetry.DecreaseReputation(
		repid.For(client.ja4Plus, client.remoteIP),
		99, "test: allowlisted source with a bad score")

	h := blockerHandler(t)

	if got := serveWithIdentity(h, client); got != http.StatusForbidden {
		t.Fatalf("without an allowlist the client got %d, want 403 — the rest of "+
			"this test would prove nothing", got)
	}

	withAllowlist(t, "203.0.113.0/24")
	if got := serveWithIdentity(h, client); got != http.StatusOK {
		t.Errorf("an allowlisted source got %d, want 200.\n"+
			"GATEON_MITIGATION_ALLOWLIST says these sources are never mitigated, and "+
			"a 403 from the reputation blocker is the most common way gateon "+
			"mitigates anything.", got)
	}
}

// TestAllowlistedSourceIsNotBannedByTheHoneypot covers the ban.
//
// This is the case with the widest blast radius: a ban lands on an address, so a
// trap hit from a customer's own scanner takes out everything sharing that
// egress until it expires.
func TestAllowlistedSourceIsNotBannedByTheHoneypot(t *testing.T) {
	resetHoneypotState(t)

	const ip = "198.51.100.50"

	blockHoneypotIP(ip, time.Now().Add(time.Hour))
	blocklistMu.RLock()
	_, bannedWithout := honeypotBlocklist[ip]
	blocklistMu.RUnlock()
	if !bannedWithout {
		t.Fatal("the address was not banned without an allowlist; the rest of this " +
			"test would prove nothing")
	}

	resetHoneypotState(t)
	withAllowlist(t, "198.51.100.0/24")

	blockHoneypotIP(ip, time.Now().Add(time.Hour))
	blocklistMu.RLock()
	_, bannedWith := honeypotBlocklist[ip]
	blocklistMu.RUnlock()
	if bannedWith {
		t.Error("an allowlisted address was banned by the honeypot. A ban is an " +
			"address-wide mitigation, so this locks out everything behind that " +
			"egress — which is precisely what the operator allowlisted it to prevent.")
	}
}

// TestAllowlistExemptsEnforcementNotObservation states the boundary.
//
// An allowlisted source stays visible: its threats are recorded, it appears in
// the dashboard and it feeds correlation. An operator who allowlists their own
// pentest team wants to see exactly what it found, and a control that hid the
// evidence along with the block would be worse than no allowlist at all.
func TestAllowlistExemptsEnforcementNotObservation(t *testing.T) {
	withAllowlist(t, "203.0.113.0/24")

	if !mitigation.IsAllowlisted("203.0.113.7") {
		t.Fatal("the address is not allowlisted; the setup is wrong")
	}

	// The recording path takes no allowlist argument and has no way to consult
	// one. That is the design, and this assertion is what stops someone "tidying"
	// an allowlist check into it later.
	before := telemetry.GetReputationScore(
		repid.For("fp-observed", "203.0.113.7"))
	telemetry.DecreaseReputation(
		repid.For("fp-observed", "203.0.113.7"), 50, "test: still recorded")
	after := telemetry.GetReputationScore(
		repid.For("fp-observed", "203.0.113.7"))

	if after >= before {
		t.Errorf("an allowlisted source's score did not move (%v → %v). The "+
			"allowlist must exempt enforcement and never observation: an operator "+
			"allowlists a scanner to stop it being blocked, not to stop seeing it.",
			before, after)
	}
}

// TestAllowlistIsOffByDefault guards the default.
//
// An allowlist that matched anything before being configured would be a
// gateway-wide bypass installed by upgrading.
func TestAllowlistIsOffByDefault(t *testing.T) {
	mitigation.SetAllowlist(nil)
	for _, ip := range []string{"203.0.113.7", "198.51.100.4", "2001:db8::1", "10.0.0.1"} {
		if mitigation.IsAllowlisted(ip) {
			t.Errorf("%s was allowlisted with nothing configured", ip)
		}
	}
	if n := mitigation.AllowlistSize(); n != 0 {
		t.Errorf("allowlist size is %d with nothing configured, want 0", n)
	}
}

// TestAllowlistMatchesIPv6AndMappedForms pins the address handling.
//
// A v4-mapped v6 address is the same host as its v4 form, and a client arriving
// over a dual-stack listener can present either. Failing to unmap would exempt a
// source on one listener and refuse it on another.
func TestAllowlistMatchesIPv6AndMappedForms(t *testing.T) {
	withAllowlist(t, "203.0.113.0/24, 2001:db8::/32")

	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.7", true},
		{"::ffff:203.0.113.7", true}, // the same host, v4-mapped
		{"2001:db8::1", true},
		{"198.51.100.4", false},
		{"2001:db9::1", false},
		{"not-an-address", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := mitigation.IsAllowlisted(tc.ip); got != tc.want {
			t.Errorf("IsAllowlisted(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestAllowlistedSourceIsNotChallengedByProofOfWork covers the challenge.
//
// A proof-of-work challenge costs the client a round trip and CPU, and an API
// client or a monitoring probe cannot solve one at all — so for a non-browser
// source this is indistinguishable from a block.
func TestAllowlistedSourceIsNotChallengedByProofOfWork(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658_pow"
	const ip = "203.0.113.7"

	// The challenge only fires below the reputation threshold, so the source has
	// to have earned a bad score first. Without this the test would pass whether
	// or not the allowlist is consulted, which is the most common way an
	// exemption test proves nothing.
	telemetry.DecreaseReputation(repid.For(browser, ip), 99, "test: pow")

	serve := func() (bool, int) {
		reached := false
		h := Pow(1, 50, "test-secret", "allowlist-test")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = ip + ":51234"
		req = req.WithContext(context.WithValue(req.Context(),
			request.RequestStateContextKey{}, &request.RequestState{JA4Plus: browser}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return reached, rr.Code
	}

	if reached, code := serve(); reached {
		t.Fatalf("the source was not challenged without an allowlist (status %d); "+
			"the rest of this test would prove nothing", code)
	}

	withAllowlist(t, "203.0.113.0/24")
	if reached, code := serve(); !reached {
		t.Errorf("an allowlisted source was challenged (status %d); a monitoring "+
			"probe or an API client cannot solve a proof-of-work challenge, so for "+
			"it this is indistinguishable from a block", code)
	}
}
