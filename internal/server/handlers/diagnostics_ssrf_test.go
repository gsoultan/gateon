// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/netip"
	"testing"
)

// TestTestTargetRefusesMetadataOutsidePrivateRanges (ADR 0077): the
// diagnostics test-target refuses loopback, private and link-local ranges,
// but Alibaba's metadata address sits in carrier-grade NAT space, Azure's
// WireServer on a public address, and a NAT64 address reaches the IPv4
// address it embeds -- none of which a range check on the literal sees.
func TestTestTargetRefusesMetadataOutsidePrivateRanges(t *testing.T) {
	for _, s := range []string{
		"100.100.100.200", "168.63.129.16", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "64:ff9b::a00:5",
	} {
		if !isBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}
	for _, s := range []string{"93.184.216.34", "100.64.0.5", "64:ff9b::5db8:d822"} {
		if isBlockedIP(netip.MustParseAddr(s)) {
			t.Errorf("isBlockedIP(%s) = true, want false: a public address", s)
		}
	}
}
