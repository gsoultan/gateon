// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"
)

// TestAddressSeenBeforeItsThreatsIsStillShunned.
//
// IPMitigation calls IsIPMitigated on every request, so by the time any threat
// from an address is processed, that address has already been looked up. A
// lookup that finds no row caches "not mitigated" as true in the shared
// unmitigated cache -- and IsIPUnmitigated, which escalateMitigation and the
// alerting shunner consult to respect an operator's manual release, read that
// same cached true as "an operator released this address". So every address
// that had ever sent a request counted as manually released, and escalation
// never shunned one: the three-fingerprint rule could only ever fire for an
// address the gateway had not seen, which in production is none of them.
func TestAddressSeenBeforeItsThreatsIsStillShunned(t *testing.T) {
	freshStore(t)
	const ip = "198.51.100.61"

	// What IPMitigation does on the attacker's first request.
	if IsIPMitigated(ip) {
		t.Fatal("a fresh address is already mitigated")
	}
	if IsIPUnmitigated(ip) {
		t.Errorf("an address nobody released reads as manually released")
	}

	for i := range ipShunUniqueUserThreshold {
		escalateMitigation(&SecurityThreat{
			Type:        "waf_block",
			Category:    "waf",
			SourceIP:    ip,
			Fingerprint: fmt.Sprintf("ja4-seen-first-%d", i),
			Mitigated:   true,
		})
	}
	if !IsIPMitigated(ip) {
		t.Errorf("%d distinct malicious fingerprints behind %s did not shun it, because the "+
			"address had made a request before its threats were processed", ipShunUniqueUserThreshold, ip)
	}

	// The release this exists to respect must still be respected.
	MarkIPUnmitigated(ip)
	if !IsIPUnmitigated(ip) {
		t.Errorf("an address an operator released does not read as released")
	}
}
