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
