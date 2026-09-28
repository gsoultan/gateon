// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// An automatic IP shun refuses every request from an address, on every route,
// and holds until an operator releases it. The escalation that writes one
// counted distinct JA4+ strings behind the address as distinct users, counted
// any refusal as an attack, and never forgot: three browser builds behind an
// office egress that each hit a rate limit shunned the office, and so did one
// client whose JA4+ changed with its method, cookie and referer. ADR 0029.
//
// Every test here goes through the recording path the gateway uses --
// RecordSecurityThreat, then the store's threat loop -- and reads the answer
// the IP block reads.

// shunJA4H is the HTTP half of an ordinary browser request's JA4+.
const shunJA4H = "ge11cr0200_5b1e5b1e5b1e"

// shunBuild is the JA4+ of the i-th client build: a TLS stack of its own.
func shunBuild(i int) string {
	return fmt.Sprintf("t13d1516h2_8daaf6152771_%012x_%s", i, shunJA4H)
}

// shunTestStore gives a test its own store and no escalation state, so that
// nothing one test (or one run of -count) records reaches the next.
func shunTestStore(t *testing.T) {
	t.Helper()
	freshStore(t)
	resetAddressEvidence()
	ResetFingerprintSightings()
	t.Cleanup(func() {
		resetAddressEvidence()
		ResetFingerprintSightings()
	})
}

// attackFrom records a request the WAF refused on its payload -- attack
// evidence -- from a client presenting fp at ip. A zero at is "now", as the
// recording path stamps it.
func attackFrom(fp, ip string, at time.Time) {
	RecordSecurityThreat(SecurityThreat{
		Type: "waf_blocked", Category: "sqli", Severity: "critical", Score: 100,
		ActionTaken: ActionBlocked, SourceIP: ip, Fingerprint: fp, Time: at,
	})
}

// shunned reports whether ip is shunned once everything recorded so far has
// been through the threat loop.
func shunned(ip string) bool {
	FlushThreats()
	return IsIPMitigated(ip)
}

// policyRefusals are decisions about who a client is, or how much it sends,
// not about what it did: a rate limit, a geo or bot-policy block, and the
// reputation refusal that follows an earlier decision.
var policyRefusals = []SecurityThreat{
	{Type: "rate_limit", Category: "abuse"},
	{Type: "geoip_block", Category: "geofencing"},
	{Type: "bot_detected", Category: "bot"},
	{Type: "reputation_block", Category: "bot", Score: 100},
}

func refuse(th SecurityThreat, fp, ip string) {
	th.SourceIP, th.Fingerprint, th.ActionTaken = ip, fp, ActionBlocked
	RecordSecurityThreat(th)
}

func TestAnOfficeWhoseBrowsersHitARateLimitIsNotShunned(t *testing.T) {
	shunTestStore(t)
	const office = "203.0.113.40"

	for i := range 3 {
		refuse(policyRefusals[0], shunBuild(i), office)
	}
	if shunned(office) {
		t.Fatalf("three browser builds behind %s each hit a rate limit, and the address was shunned: "+
			"everyone behind the office egress is refused until an operator releases it", office)
	}

	// As many builds as it would take to shun, each refused by policy.
	for i := range ipShunMinClasses {
		refuse(policyRefusals[i%len(policyRefusals)], shunBuild(10+i), office)
	}
	if shunned(office) {
		t.Errorf("%d browser builds behind %s were refused by rate-limit, geo, bot and reputation "+
			"policy, and the address was shunned; none of those is evidence of an attack",
			ipShunMinClasses+3, office)
	}
}

// The method, and whether a Cookie and a Referer were sent, change from one
// request to the next for one browser, and they are part of its JA4+.
var oneBrowsersJA4H = []string{
	"ge11cr0200_5b1e5b1e5b1e", "ge11cn0200_5b1e5b1e5b1e",
	"ge11nr0200_5b1e5b1e5b1e", "ge11nn0200_5b1e5b1e5b1e",
	"po11cr0200_5b1e5b1e5b1e", "po11cn0200_5b1e5b1e5b1e",
	"po11nr0200_5b1e5b1e5b1e", "po11nn0200_5b1e5b1e5b1e",
}

func TestAClientVaryingItsHeaderBitsIsOneClass(t *testing.T) {
	shunTestStore(t)
	for _, tc := range []struct{ name, ja4, ip string }{
		{"tls", "t13d1516h2_8daaf6152771_5b1e5b1e0001", "203.0.113.41"},
		{"plaintext", "", "203.0.113.42"},
	} {
		for _, ja4h := range oneBrowsersJA4H {
			attackFrom(tc.ja4+"_"+ja4h, tc.ip, time.Time{})
		}
		if shunned(tc.ip) {
			t.Errorf("%s: one client sent %d requests the WAF refused, varying only its method, cookie "+
				"and referer, and %s was shunned as if %d users had attacked from it",
				tc.name, len(oneBrowsersJA4H), tc.ip, len(oneBrowsersJA4H))
		}
	}
}

func TestAttackingClassesAtTheThresholdShunTheAddress(t *testing.T) {
	shunTestStore(t)
	const ip = "203.0.113.43"

	for i := range ipShunMinClasses - 1 {
		attackFrom(shunBuild(i), ip, time.Time{})
	}
	if shunned(ip) {
		t.Fatalf("%d client builds attacking from %s shunned it; the bar is %d",
			ipShunMinClasses-1, ip, ipShunMinClasses)
	}
	attackFrom(shunBuild(ipShunMinClasses-1), ip, time.Time{})
	if !shunned(ip) {
		t.Errorf("%d client builds attacked from %s within %s and it was not shunned",
			ipShunMinClasses, ip, mitigationEvidenceWindow)
	}
}

// Four client builds attacking repeatedly from one address is what an office
// with a few infected machines looks like. Each build is contained on the
// office's network by the fingerprint block (ADR 0026) -- which is why the
// address is not shunned: a shun would add only the office's other users,
// until an operator noticed. This pins the bar ADR 0029 decided; the test
// above follows whatever ipShunMinClasses says, so it cannot.
func TestAFewInfectedMachinesBehindOneAddressAreContainedNotShunned(t *testing.T) {
	shunTestStore(t)
	const office, infected = "203.0.113.48", 4
	for i := range infected {
		for range 3 {
			attackFrom(shunBuild(i), office, time.Time{})
		}
	}
	if shunned(office) {
		t.Errorf("%d client builds attacking from %s shunned it; an office with a few infected "+
			"machines is contained build by build, not taken offline", infected, office)
	}
	for i := range infected {
		if !IsUserMitigated(repid.For(shunBuild(i), office)) {
			t.Errorf("build %d attacked three times from %s and is not blocked on its network", i, office)
		}
	}
}

func TestEvidenceOlderThanTheWindowDoesNotCount(t *testing.T) {
	shunTestStore(t)
	now := time.Now()
	for _, tc := range []struct {
		ip   string
		age  time.Duration
		want bool
	}{
		{"203.0.113.44", mitigationEvidenceWindow + time.Minute, false},
		// The control: the same evidence, inside the window, is a shun.
		{"203.0.113.45", mitigationEvidenceWindow - time.Minute, true},
	} {
		for i := range ipShunMinClasses - 1 {
			attackFrom(shunBuild(i), tc.ip, now.Add(-tc.age))
		}
		attackFrom(shunBuild(ipShunMinClasses-1), tc.ip, now)
		if got := shunned(tc.ip); got != tc.want {
			t.Errorf("%d builds attacked %s before one more did: shunned = %v, want %v (window %s)",
				ipShunMinClasses-1, tc.age, got, tc.want, mitigationEvidenceWindow)
		}
	}
}

func TestAnAllowlistedAddressIsNotShunned(t *testing.T) {
	shunTestStore(t)
	const ip = "203.0.113.46"
	mitigation.SetAllowlist(mitigation.ParseAllowlist(ip + "/32"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	for i := range ipShunMinClasses {
		attackFrom(shunBuild(i), ip, time.Time{})
	}
	if shunned(ip) {
		t.Fatalf("%s is on GATEON_MITIGATION_ALLOWLIST and was shunned", ip)
	}

	// Off the allowlist, what it did while it was on it is not held against it.
	mitigation.SetAllowlist(nil)
	attackFrom(shunBuild(ipShunMinClasses), ip, time.Time{})
	if shunned(ip) {
		t.Fatalf("%s was shunned by evidence recorded while it was allowlisted", ip)
	}
	// The control: evidence it earns now counts.
	for i := range ipShunMinClasses - 1 {
		attackFrom(shunBuild(100+i), ip, time.Time{})
	}
	if !shunned(ip) {
		t.Errorf("%d builds attacked from %s after it left the allowlist and it was not shunned",
			ipShunMinClasses, ip)
	}
}

// An operator's release holds against the evidence that earned the shun.
func TestAReleasedAddressIsNotShunnedByOldEvidence(t *testing.T) {
	shunTestStore(t)
	const ip = "203.0.113.47"
	for i := range ipShunMinClasses {
		attackFrom(shunBuild(i), ip, time.Time{})
	}
	if !shunned(ip) {
		t.Fatalf("setup: %d attacking builds did not shun %s", ipShunMinClasses, ip)
	}
	if err := MarkIPUnmitigated(ip); err != nil {
		t.Fatalf("release: %v", err)
	}

	for i := range ipShunMinClasses {
		attackFrom(shunBuild(i), ip, time.Time{})
	}
	if shunned(ip) {
		t.Errorf("%s was shunned again, by the builds that earned the shun an operator had just released", ip)
	}
}
