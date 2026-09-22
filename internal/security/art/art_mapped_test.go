// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package art

import (
	"net/netip"
	"testing"
)

// TestContainsAddrMatchesIPv4MappedForms closes a hole in every deny list
// built on this tree.
//
// An IPv4-mapped IPv6 address -- ::ffff:203.0.113.5 -- reports Is4In6 rather
// than Is4, so it searched the IPv6 trie and missed every IPv4 rule. A deny
// list naming 203.0.113.0/24 did not match a client arriving in the mapped
// form, and that form is reachable from behind a configured trusted proxy,
// where GetClientIP returns the X-Forwarded-For value verbatim.
func TestContainsAddrMatchesIPv4MappedForms(t *testing.T) {
	tree := NewTree()
	if err := tree.InsertCIDR("203.0.113.0/24"); err != nil {
		t.Fatalf("InsertCIDR: %v", err)
	}

	plain := netip.MustParseAddr("203.0.113.5")
	if !tree.ContainsAddr(plain) {
		t.Fatal("the plain IPv4 form did not match its own /24")
	}

	mapped := netip.MustParseAddr("::ffff:203.0.113.5")
	if !tree.ContainsAddr(mapped) {
		t.Error("the IPv4-mapped form did not match a rule its plain form does; " +
			"a client presenting ::ffff:<addr> walks past every IPv4 deny rule")
	}

	// An address genuinely outside the range must still not match, in either
	// form -- otherwise the fix is just "match everything".
	if tree.ContainsAddr(netip.MustParseAddr("198.51.100.1")) {
		t.Error("an unrelated IPv4 address matched")
	}
	if tree.ContainsAddr(netip.MustParseAddr("::ffff:198.51.100.1")) {
		t.Error("an unrelated mapped address matched")
	}
	// A real IPv6 address must still route to the v6 trie.
	if tree.ContainsAddr(netip.MustParseAddr("2001:db8::1")) {
		t.Error("an IPv6 address matched an IPv4-only tree")
	}
}
