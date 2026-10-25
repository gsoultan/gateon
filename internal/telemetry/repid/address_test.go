// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package repid

import "testing"

// Address and AddressKey are the one keying of an address-level decision: the
// shun's evidence, the block list and its enforcement (ADR 0058). The
// behaviour they produce is tested in internal/telemetry; these pin the key.
func TestAddressKeyKeysIPv6ByItsSlashSixtyFourAndIPv4ByItself(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2::5", "2001:db8:1:2::"},
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::"},
		{"2001:db8:1:2::", "2001:db8:1:2::"},
		{"fe80::1%eth0", "fe80::"},
		{"::1", "::"},
		{"not-an-address", "not-an-address"},
		{"bad::address::x", "bad::address::x"},
		{"", ""},
	} {
		if got := AddressKey(c.in); got != c.want {
			t.Errorf("AddressKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Every address of one /64 has one key, and the key is a fixed point: a key
// shown in the dashboard and sent back to release it lands on the same row.
func TestAddressKeyIsOneKeyPerSlashSixtyFourAndAFixedPoint(t *testing.T) {
	a := AddressKey("2001:db8:aa:bb::1")
	if b := AddressKey("2001:db8:aa:bb:1:2:3:4"); a != b {
		t.Fatalf("two addresses of one /64 have keys %q and %q", a, b)
	}
	if AddressKey(a) != a {
		t.Fatalf("AddressKey(%q) = %q; a key must be its own key", a, AddressKey(a))
	}
	if c := AddressKey("2001:db8:aa:bc::1"); c == a {
		t.Fatal("the neighbouring /64 has the same key")
	}
	if addr, ok := Address(a); !ok || addr.String() != a {
		t.Fatalf("Address(%q) = %v, %v", a, addr, ok)
	}
	if _, ok := Address("nope"); ok {
		t.Fatal("Address accepted text that is not an address")
	}
}

// ForAddress is the reputation score's key (ADR 0079): the class For keys a
// network by, on one address -- an IPv4 address itself, an IPv6 address's /64.
func TestForAddressKeysTheClassOnOneAddress(t *testing.T) {
	const build = "t13d1516h2_8daaf6152771_b0da82dd1658_ge11cr0200_7e33b58890ac"
	class := Class(build)
	for _, c := range []struct{ fp, ip, want string }{
		{build, "203.0.113.7", class + "|203.0.113.7"},
		{build, "::ffff:203.0.113.7", class + "|203.0.113.7"},
		{build, "2001:db8:1:2::5", class + "|2001:db8:1:2::"},
		{"", "203.0.113.7", "203.0.113.7"},
		{"", "2001:db8:1:2::5", "2001:db8:1:2::"},
		{build, "", class + "|"},
	} {
		if got := ForAddress(c.fp, c.ip); got != c.want {
			t.Errorf("ForAddress(%q, %q) = %q, want %q", c.fp, c.ip, got, c.want)
		}
	}
	if ForAddress(build, "203.0.113.7") == ForAddress(build, "203.0.113.8") {
		t.Error("two IPv4 addresses on one /24 share a score key")
	}
	if ForAddress(build, "2001:db8:1:2::5") != ForAddress(build, "2001:db8:1:2:ffff::1") {
		t.Error("two addresses of one IPv6 /64 have different score keys")
	}
	if k := ForAddress(build, "203.0.113.7"); !Scoped(k) || ClassOf(k) != class {
		t.Errorf("ForAddress key %q is not scoped to its class %q", k, class)
	}
}
