// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ha

import (
	"net"
	"testing"
)

func ip(s string) net.IP { return net.ParseIP(s) }

func TestPriorityDecidesWhenItDiffers(t *testing.T) {
	lower, higher := ip("10.0.0.1"), ip("10.0.0.2")

	if !peerOutranks(200, 100, lower, higher) {
		t.Error("a higher-priority peer did not outrank us, even holding the lower address")
	}
	if peerOutranks(100, 200, higher, lower) {
		t.Error("a lower-priority peer outranked us, even holding the higher address")
	}
}

// TestEqualPrioritiesResolveToExactlyOneMaster is the regression guard.
//
// The equal case previously had no rule: a peer at the same priority refreshed
// lastSeen and nothing else, so neither node released. Both waited out three
// intervals seeing no master, both acquired the VIP, and both stayed master.
// Two nodes holding one address, indefinitely.
//
// The property that matters is not which node wins but that the two evaluate
// the same rule to opposite answers.
func TestEqualPrioritiesResolveToExactlyOneMaster(t *testing.T) {
	a, b := ip("10.0.0.1"), ip("10.0.0.2")

	aYields := peerOutranks(100, 100, b, a) // node A, seeing B
	bYields := peerOutranks(100, 100, a, b) // node B, seeing A

	if aYields == bYields {
		t.Fatalf("both nodes reached the same verdict (yield=%v); "+
			"that is either two masters or none", aYields)
	}
	// Higher address wins, as VRRP does.
	if !aYields {
		t.Error("the node with the lower address did not yield")
	}
}

// Byte comparison, not string. "10.0.0.9" sorts above "10.0.0.10" lexically,
// which would make the winner depend on how an address happens to be written.
func TestTieBreakComparesAddressesNumerically(t *testing.T) {
	nine, ten := ip("10.0.0.9"), ip("10.0.0.10")

	if peerOutranks(100, 100, nine, ten) {
		t.Error("10.0.0.9 outranked 10.0.0.10; the comparison is lexical, not numeric")
	}
	if !peerOutranks(100, 100, ten, nine) {
		t.Error("10.0.0.10 did not outrank 10.0.0.9")
	}
}

// Without a local address there is no tie-break to apply. Yielding is the safer
// half: a node that wrongly yields leaves the pair briefly with no master and
// recovers on its own, while a node that wrongly holds gives two masters for one
// address, which does not recover.
func TestUnknownLocalAddressYields(t *testing.T) {
	if !peerOutranks(100, 100, ip("10.0.0.1"), nil) {
		t.Error("a node that cannot identify itself did not yield on a tie")
	}
	// The mirror: a peer we cannot place does not get to displace us.
	if peerOutranks(100, 100, nil, ip("10.0.0.1")) {
		t.Error("a peer with no usable address displaced a node that knows its own")
	}
}

// A three-node pool must still elect exactly one master: every node yields
// except the one that outranks all others.
func TestOnlyOneNodeHoldsAcrossAPool(t *testing.T) {
	nodes := []struct {
		name     string
		priority int32
		addr     net.IP
	}{
		{"a", 100, ip("10.0.0.1")},
		{"b", 100, ip("10.0.0.2")},
		{"c", 100, ip("10.0.0.3")},
	}

	holders := 0
	for _, me := range nodes {
		yields := false
		for _, peer := range nodes {
			if peer.name == me.name {
				continue
			}
			if peerOutranks(peer.priority, me.priority, peer.addr, me.addr) {
				yields = true
			}
		}
		if !yields {
			holders++
			if me.name != "c" {
				t.Errorf("%s held the VIP; the highest address should win", me.name)
			}
		}
	}
	if holders != 1 {
		t.Fatalf("%d nodes would hold the VIP, want exactly 1", holders)
	}
}

// haInterfaceIP must degrade to nil rather than guessing, since a wrong identity
// would make the tie-break non-deterministic.
func TestInterfaceLookupDegradesToNil(t *testing.T) {
	for _, name := range []string{"", "definitely-not-an-interface"} {
		if got := haInterfaceIP(name); got != nil {
			t.Errorf("haInterfaceIP(%q) = %v, want nil", name, got)
		}
	}
}
