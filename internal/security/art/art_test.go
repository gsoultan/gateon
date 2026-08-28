// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package art

import (
	"net/netip"
	"testing"
)

func mustInsert(t *testing.T, tree *Tree, cidrs ...string) {
	t.Helper()
	for _, c := range cidrs {
		if err := tree.InsertCIDR(c); err != nil {
			t.Fatalf("InsertCIDR(%q): %v", c, err)
		}
	}
}

func TestByteAlignedCIDRs(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	mustInsert(t, tree, "10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/16")

	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"192.168.1.7", true},
		{"192.168.2.7", false},
		{"172.16.99.1", true},
		{"172.17.0.1", false},
	} {
		if got := tree.Contains(tc.ip); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestNonByteAlignedCIDRsMatchTheirWholeRange is the bug.
//
// insert masks the final partial byte and stores that single value, while
// search walks byte-by-byte comparing exactly. So 10.16.0.0/12 was stored under
// the byte 0x10 and only ever matched addresses whose second byte was literally
// 0x10 -- a /12 behaving as a /16, and matching 1/16th of what it claims.
//
// Both consumers are harmed, in opposite directions. internal/request tracks
// trusted proxies and Cloudflare ranges here, and Cloudflare publishes almost
// nothing byte-aligned; a real Cloudflare address not recognised as one means
// the forwarded client-IP header is distrusted and every request collapses onto
// the edge's own address, taking per-IP rate limiting and reputation with it.
// internal/middleware keeps a deny tree here, and a deny rule that silently
// stops denying is fail-open.
func TestNonByteAlignedCIDRsMatchTheirWholeRange(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		cidr string
		in   []string
		out  []string
	}{
		{"10.16.0.0/12",
			[]string{"10.16.0.0", "10.20.5.5", "10.31.255.255"},
			[]string{"10.15.255.255", "10.32.0.0"}},
		{"203.0.113.0/25",
			[]string{"203.0.113.0", "203.0.113.50", "203.0.113.127"},
			[]string{"203.0.113.128", "203.0.113.255"}},
		{"192.0.2.0/23",
			[]string{"192.0.2.1", "192.0.3.254"},
			[]string{"192.0.1.255", "192.0.4.0"}},
		// Real Cloudflare ranges. None are byte-aligned, which is the point.
		{"173.245.48.0/20",
			[]string{"173.245.48.1", "173.245.55.9", "173.245.63.255"},
			[]string{"173.245.47.255", "173.245.64.0"}},
		{"103.21.244.0/22",
			[]string{"103.21.244.1", "103.21.247.255"},
			[]string{"103.21.243.255", "103.21.248.0"}},
		{"172.64.0.0/13",
			[]string{"172.64.0.1", "172.70.1.1", "172.71.255.255"},
			[]string{"172.63.255.255", "172.72.0.0"}},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			t.Parallel()

			tree := NewTree()
			mustInsert(t, tree, tc.cidr)

			for _, ip := range tc.in {
				if !tree.Contains(ip) {
					t.Errorf("%s does not contain %s, but the range does", tc.cidr, ip)
				}
			}
			for _, ip := range tc.out {
				if tree.Contains(ip) {
					t.Errorf("%s contains %s, which is outside the range", tc.cidr, ip)
				}
			}
		})
	}
}

func TestIPv6(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	mustInsert(t, tree, "2001:db8::/32", "2606:4700::/44")

	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"2001:db8::1", true},
		{"2001:db8:ffff::1", true},
		{"2001:db9::1", false},
		{"2606:4700::1", true},
		{"2606:4700:f::1", true},
		{"2606:4701::1", false},
	} {
		if got := tree.Contains(tc.ip); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestV4AndV6AreSeparate guards against an address family matching the other's
// tree, which would let an IPv6 client inherit an IPv4 trust decision.
func TestV4AndV6AreSeparate(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	mustInsert(t, tree, "10.0.0.0/8")

	if tree.Contains("::1") {
		t.Error("an IPv4 CIDR matched an IPv6 address")
	}

	v6 := NewTree()
	mustInsert(t, v6, "2001:db8::/32")
	if v6.Contains("10.0.0.1") {
		t.Error("an IPv6 CIDR matched an IPv4 address")
	}
}

func TestDefaultRouteMatchesEverything(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	mustInsert(t, tree, "0.0.0.0/0")

	for _, ip := range []string{"1.2.3.4", "255.255.255.255", "10.0.0.1"} {
		if !tree.Contains(ip) {
			t.Errorf("0.0.0.0/0 does not contain %s", ip)
		}
	}
}

func TestEmptyTreeContainsNothing(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	if !tree.IsEmpty() {
		t.Error("a fresh tree is not empty")
	}
	if tree.Contains("10.0.0.1") {
		t.Error("an empty tree matched an address")
	}

	mustInsert(t, tree, "10.0.0.0/8")
	if tree.IsEmpty() {
		t.Error("a tree with a CIDR reports empty")
	}
}

func TestInvalidInputIsRejected(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	for _, bad := range []string{"", "not-a-cidr", "10.0.0.1", "10.0.0.0/33", "::/129"} {
		if err := tree.InsertCIDR(bad); err == nil {
			t.Errorf("InsertCIDR(%q) accepted an invalid CIDR", bad)
		}
	}
	// A malformed address must not match, and must not panic.
	if tree.Contains("not-an-ip") {
		t.Error("a malformed address matched")
	}
}

func TestContainsAddrMatchesContains(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	mustInsert(t, tree, "10.16.0.0/12")

	addr := netip.MustParseAddr("10.20.1.1")
	if tree.ContainsAddr(addr) != tree.Contains(addr.String()) {
		t.Error("ContainsAddr and Contains disagree")
	}
}

// TestOverlappingCIDRsKeepTheBroaderMatch checks that inserting a narrow range
// after a broad one does not shadow it.
func TestOverlappingCIDRsKeepTheBroaderMatch(t *testing.T) {
	t.Parallel()

	tree := NewTree()
	mustInsert(t, tree, "10.0.0.0/8", "10.1.2.0/24")

	for _, ip := range []string{"10.1.2.3", "10.99.99.99"} {
		if !tree.Contains(ip) {
			t.Errorf("Contains(%q) = false; the /8 still covers it", ip)
		}
	}
}
