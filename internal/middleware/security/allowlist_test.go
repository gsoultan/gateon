// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"context"
	"path/filepath"
	"testing"
	"time"

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

// The proof-of-work case moved to package challenge's allowlist_test.go with
// the code it drives (ADR-0030), as the reputation and mitigation cases moved to
// package identity's under ADR-0013.

// withAllowlist installs an allowlist for the duration of a test. challenge and
// identity each carry the same three lines.
func withAllowlist(t *testing.T, cidrs string) {
	t.Helper()
	mitigation.SetAllowlist(mitigation.ParseAllowlist(cidrs))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
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
//
// The reputation score is on the enforcement side of that line. This test
// used to assert the opposite -- that an allowlisted source's threats still
// lowered its score, "observation" in the 2026-09-05 decision -- which was
// right while a score belonged to one client. Since ADR 0024 it belongs to a
// client class on a network, and the reputation blocker refuses every client
// of the class there once it falls: an allowlisted scanner's threats lowering
// it refused the scanner's neighbours running the same build, enforcement
// landing on clients the operator never named, for traffic the operator said
// not to act on. So the score is an enforcement input and the allowlist
// exempts it (ADR 0031); the record is what stays.
func TestAllowlistExemptsEnforcementNotObservation(t *testing.T) {
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	t.Setenv("GATEON_TRACE_DIR", t.TempDir())
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "observation.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })
	withAllowlist(t, "203.0.113.0/24")
	const ip, build = "203.0.113.7", "t13d1516h2_8daaf6152771_b0da82dd1658_observed"
	id := repid.For(build, ip)
	t.Cleanup(func() { telemetry.ResetReputation(id) })

	if !mitigation.IsAllowlisted(ip) {
		t.Fatal("the address is not allowlisted; the setup is wrong")
	}

	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
		Type: "waf_blocked", Category: "waf", Severity: "high", SourceIP: ip, Fingerprint: build,
		Score: 100, Time: time.Now(), ActionTaken: telemetry.ActionBlocked,
	})
	telemetry.FlushThreats()

	recorded := 0
	for _, th := range telemetry.GetSecurityThreatsLite(t.Context(), 100, 0, nil) {
		if th.SourceIP == ip {
			recorded++
		}
	}
	if recorded != 1 {
		t.Errorf("%d of the allowlisted source's 1 threat is recorded. The allowlist must "+
			"never hide observation: an operator allowlists a scanner to stop it being "+
			"blocked, not to stop seeing it.", recorded)
	}
	if got := telemetry.GetReputationScore(id); got < 100 {
		t.Errorf("an allowlisted source's threat lowered the score its build holds on its "+
			"network to %v. That score is enforced against every client of the build there "+
			"(ADR 0024), so it is enforcement, which the allowlist exempts (ADR 0031).", got)
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
