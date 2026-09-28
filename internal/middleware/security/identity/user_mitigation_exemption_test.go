// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// GATEON_MITIGATION_ALLOWLIST is "never mitigated", and the reputation blocker
// behind UserMitigation honours it, and loopback, before it refuses anyone.
// UserMitigation honoured neither: a fingerprint block is kept for a build on
// a /24 or /64 (ADR 0026), so an allowlisted address on a network where someone
// else earned a block on its build was refused with it. ADR 0029.

// A client the allowlist names is served whatever block its build has on its
// network.
func TestAnAllowlistedClientIsNotRefusedByAFingerprintBlock(t *testing.T) {
	scopeTestStore(t)
	// Earned by an attacker on the /24, not by the allowlisted address.
	recordThreats(3, wafBlock(chromeJA4Plus, "203.0.113.7"))
	const allowlisted = "203.0.113.50"
	if code, _ := userMitigationStatus(chromeJA4Plus, allowlisted); code != http.StatusForbidden {
		t.Fatalf("setup: the attacker's build is not blocked on its network (%d); the rest proves nothing", code)
	}

	withAllowlist(t, allowlisted+"/32")
	if code, body := userMitigationStatus(chromeJA4Plus, allowlisted); code != http.StatusOK {
		t.Errorf("%s is on GATEON_MITIGATION_ALLOWLIST and a fingerprint block refused it: %d %q",
			allowlisted, code, body)
	}
	if code, _ := userMitigationStatus(chromeJA4Plus, "203.0.113.7"); code != http.StatusForbidden {
		t.Errorf("the allowlist lifted the block for an address it does not name (%d)", code)
	}
}

// Loopback is exempt, as it is from the reputation blocker: behind a local
// proxy that sets no forwarding header every client is loopback, and a block
// on loopback's network refuses them all.
func TestLoopbackIsNotRefusedByAFingerprintBlock(t *testing.T) {
	scopeTestStore(t)
	for _, ip := range []string{"127.0.0.1", "203.0.113.60"} {
		telemetry.MarkUserMitigated(repid.For(chromeJA4Plus, ip), "JA4+", "test: a block on the client's network", "waf")
	}
	if code, _ := userMitigationStatus(chromeJA4Plus, "203.0.113.60"); code != http.StatusForbidden {
		t.Fatalf("control: a blocked build on an ordinary network got %d, want 403", code)
	}
	if code, _ := userMitigationStatus(chromeJA4Plus, "127.0.0.1"); code != http.StatusOK {
		t.Errorf("a loopback client with a blocked build got %d, want 200", code)
	}
}

// An allowlisted source's attacks are recorded and never turned into a block.
// A block is kept for its build on its network, so one earned by an allowlisted
// scanner refuses the scanner's neighbours who share the build -- enforcement
// the allowlist is there to prevent, landing on people it does not even name.
func TestAnAllowlistedSourceDoesNotEarnAFingerprintBlock(t *testing.T) {
	scopeTestStore(t)
	const scanner, neighbour = "203.0.113.50", "203.0.113.51"
	withAllowlist(t, scanner+"/32")

	recordThreats(3, wafBlock(chromeJA4Plus, scanner))
	if code, _ := userMitigationStatus(chromeJA4Plus, neighbour); code != http.StatusOK {
		t.Errorf("an allowlisted scanner's three WAF blocks blocked its build on its network: "+
			"its neighbour %s got %d", neighbour, code)
	}
	if got := threatsFrom(t, scanner); got != 3 {
		t.Errorf("%d of the allowlisted scanner's 3 threats were recorded; the allowlist exempts "+
			"enforcement, never observation", got)
	}
}

// threatsFrom counts the threats the store holds from ip.
func threatsFrom(t *testing.T, ip string) int {
	t.Helper()
	n := 0
	for _, th := range telemetry.GetSecurityThreatsLite(t.Context(), 1000, 0, nil) {
		if th.SourceIP == ip {
			n++
		}
	}
	return n
}
