// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/netip"
	"testing"
)

// TestAddrFilterMatchesTheHTTPFilter: the connection form of the ip filter, used
// on TCP routes, must decide as the request form does -- the same bare-IPv6
// host rule, the same deny-first order -- and must judge an IPv4-mapped peer as
// the IPv4 address the lists are written in.
func TestAddrFilterMatchesTheHTTPFilter(t *testing.T) {
	allow, err := NewAddrFilter(map[string]string{"allow_list": "10.0.0.0/8,2001:db8::1", "deny_list": "10.0.0.9"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for addr, want := range map[string]bool{
		"10.1.2.3":         true,
		"::ffff:10.1.2.3":  true,
		"10.0.0.9":         false, // deny wins over a containing allow
		"2001:db8::1":      true,
		"2001:db8::2":      false, // a bare IPv6 entry is one host, not its /32
		"203.0.113.7":      false,
		"::ffff:127.0.0.1": false,
	} {
		if got := allow(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s admitted = %v, want %v", addr, got, want)
		}
	}
	if _, err := NewAddrFilter(map[string]string{"allow_list": "10.0.0.*"}); err == nil {
		t.Fatal("a wildcard entry built; it would restrict nothing")
	}
}
