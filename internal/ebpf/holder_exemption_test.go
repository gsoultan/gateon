// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"net/netip"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/mitigation"
)

// withAllowlist installs prefixes for the duration of a test and clears the
// process-wide allowlist afterwards, so a shuffled run cannot leak one test's
// list into another's.
func withAllowlist(t *testing.T, prefixes ...string) {
	t.Helper()
	parsed := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		parsed = append(parsed, netip.MustParsePrefix(p))
	}
	mitigation.SetAllowlist(parsed)
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
}

// TestHolderDoesNotPushAnExemptAddressToTheKernel is the kernel half of ADR
// 0032's one rule: an address the operator has also allowlisted, and loopback,
// are served by every HTTP and TCP entrypoint (exemptFromEnforcement), so the
// kernel shun map must not drop them below the paths that serve them (ADR 0035).
// The Holder is the one point every kernel shun funnels through -- the operator
// block (MarkIPMitigated -> adapter -> Holder.ShunIP), the DDoS mitigation
// (diagnostics s.EbpfManager.ShunIP == Holder.ShunIP) and the automatic shun
// (ShunAutomatically -> Holder.ShunIPUntil) alike -- so the gate lives here and
// no caller can get past it.
//
// It uses the real production predicate (mitigation.ExemptFromEnforcement), not
// a stand-in, so the test cannot pass while the rule the request path enforces
// says something different.
func TestHolderDoesNotPushAnExemptAddressToTheKernel(t *testing.T) {
	withAllowlist(t, "203.0.113.0/24")

	cases := []struct {
		name       string
		ip         string
		wantPushed bool
	}{
		{"allowlisted address", "203.0.113.9", false},
		{"loopback v4", "127.0.0.1", false},
		{"loopback v6", "::1", false},
		{"non-exempt address", "198.51.100.7", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubManager{}
			h := NewHolder(stub)
			h.SetExemption(mitigation.ExemptFromEnforcement)

			if err := h.ShunIP(tc.ip); err != nil {
				t.Fatalf("ShunIP(%q) = %v; want nil", tc.ip, err)
			}

			pushed := stub.callCount > 0
			if pushed != tc.wantPushed {
				t.Fatalf("ShunIP(%q): pushed to kernel = %v (lastShun %q); want %v",
					tc.ip, pushed, stub.lastShun, tc.wantPushed)
			}
			if tc.wantPushed && stub.lastShun != tc.ip {
				t.Fatalf("ShunIP(%q) reached the kernel as %q", tc.ip, stub.lastShun)
			}
		})
	}
}

// TestHolderDoesNotLeaseAnExemptAutomaticShun covers the leased path the
// automatic shun takes (ShunIPUntil): the same gate applies, so an allowlisted
// or loopback address is neither pushed nor given a lease that a sweep would
// later have to lift.
func TestHolderDoesNotLeaseAnExemptAutomaticShun(t *testing.T) {
	withAllowlist(t, "203.0.113.0/24")

	until := time.Now().Add(time.Hour)

	exempt := &stubManager{}
	he := NewHolder(exempt)
	he.SetExemption(mitigation.ExemptFromEnforcement)
	if err := he.ShunIPUntil("203.0.113.42", until); err != nil {
		t.Fatalf("ShunIPUntil(allowlisted) = %v; want nil", err)
	}
	if exempt.callCount != 0 {
		t.Fatalf("an allowlisted automatic shun reached the kernel as %q", exempt.lastShun)
	}
	if _, leased := he.shuns.entries["203.0.113.42"]; leased {
		t.Fatal("an allowlisted automatic shun took a kernel lease")
	}

	live := &stubManager{}
	hl := NewHolder(live)
	hl.SetExemption(mitigation.ExemptFromEnforcement)
	if err := hl.ShunIPUntil("198.51.100.8", until); err != nil {
		t.Fatalf("ShunIPUntil(non-exempt) = %v; want nil", err)
	}
	if live.callCount != 1 || live.lastShun != "198.51.100.8" {
		t.Fatalf("a non-exempt automatic shun did not reach the kernel: count %d, last %q",
			live.callCount, live.lastShun)
	}
}

// TestHolderWithNoExemptionPushesEverything pins that a Holder with no predicate
// installed -- the zero value, and what a build with no policy leaves -- gates
// nothing, so the gate is opt-in and cannot silently swallow a shun on a path
// that never wired it.
func TestHolderWithNoExemptionPushesEverything(t *testing.T) {
	stub := &stubManager{}
	h := NewHolder(stub)
	// No SetExemption call.
	if err := h.ShunIP("127.0.0.1"); err != nil {
		t.Fatalf("ShunIP = %v; want nil", err)
	}
	if stub.callCount != 1 || stub.lastShun != "127.0.0.1" {
		t.Fatalf("with no exemption installed, ShunIP must reach the kernel: count %d, last %q",
			stub.callCount, stub.lastShun)
	}
}
