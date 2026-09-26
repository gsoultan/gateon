// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// TestPrefix64KeyIsTheSlash64: an IPv6 client can send from any address in its
// /64, so a shun or a limit keyed per address is evaded by changing the last 64
// bits. Two addresses in one /64 must share a key; the next /64 must not.
func TestPrefix64KeyIsTheSlash64(t *testing.T) {
	a := prefix64Key(net.ParseIP("2001:db8:1:2::10"))
	b := prefix64Key(net.ParseIP("2001:db8:1:2:ffff:ffff:ffff:ffff"))
	c := prefix64Key(net.ParseIP("2001:db8:1:3::10"))
	if a != b {
		t.Errorf("two addresses in 2001:db8:1:2::/64 got different keys %#x and %#x", a, b)
	}
	if a == c {
		t.Errorf("2001:db8:1:2::/64 and 2001:db8:1:3::/64 share key %#x", a)
	}
	if got := prefix64String(a); got != "2001:db8:1:2::/64" {
		t.Errorf("prefix64String = %q, want 2001:db8:1:2::/64", got)
	}
}

// TestPrefix64KeyMarshalsToTheHeaderBytes: cilium/ebpf marshals a uint64 key
// in the host's order, and the program reads the prefix's bytes as they sit in
// the header. The IPv4 key once got this backwards, and every shun landed on
// an unrelated host.
func TestPrefix64KeyMarshalsToTheHeaderBytes(t *testing.T) {
	ip := net.ParseIP("2001:db8:1:2::10")
	var marshalled [8]byte
	binary.NativeEndian.PutUint64(marshalled[:], prefix64Key(ip))
	if !bytes.Equal(marshalled[:], ip.To16()[:8]) {
		t.Errorf("the key marshals to % x, want the header's % x", marshalled, ip.To16()[:8])
	}
}

func TestShunKeyRoutesByFamily(t *testing.T) {
	for _, tc := range []struct {
		ip, wantMap string
	}{
		{"203.0.113.9", "shunned_ips"},
		{"::ffff:203.0.113.9", "shunned_ips"}, // the mapped spelling is IPv4
		{"2001:db8::9", "shunned_prefixes6"},
	} {
		mapName, _, err := shunKey(tc.ip)
		if err != nil || mapName != tc.wantMap {
			t.Errorf("shunKey(%q) = %q, %v; want %q", tc.ip, mapName, err, tc.wantMap)
		}
	}
	for _, bad := range []string{"", "not-an-ip", "2001:db8::/64", "203.0.113.0/24"} {
		if _, _, err := shunKey(bad); err == nil {
			t.Errorf("shunKey(%q) returned no error; an unencodable address must not become a key", bad)
		}
	}
}
