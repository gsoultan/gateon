// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// These cover the parts of the manager that are not behind a build tag, which is
// why they run everywhere. The XDP map operations themselves need a Linux kernel
// and are exercised by the _linux tests; what is here is the arithmetic those
// operations depend on and the bookkeeping around them.

// TestIPToUint32IsNetworkByteOrder pins the conversion that decides which
// address gets blocked.
//
// The value becomes the key in the shunned_ips map, and the XDP program looks it
// up against the source address it reads straight out of the packet header,
// which is big-endian. Get the order wrong and 1.2.3.4 is stored as 4.3.2.1:
// every shun blocks an unrelated host and the attacker is never touched, with
// nothing in any log to say so.
func TestIPToUint32IsNetworkByteOrder(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want uint32
	}{
		{"0.0.0.0", 0x00000000},
		{"1.2.3.4", 0x01020304},
		{"127.0.0.1", 0x7f000001},
		{"192.168.1.1", 0xc0a80101},
		{"255.255.255.255", 0xffffffff},
		{"203.0.113.10", 0xcb00710a},
	} {
		got, err := ipToUint32(tc.ip)
		if err != nil {
			t.Errorf("ipToUint32(%q): %v", tc.ip, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ipToUint32(%q) = %#08x, want %#08x. The XDP program compares "+
				"this against the source address in the packet header, which is "+
				"big-endian; a byte-swapped key blocks a different host entirely.",
				tc.ip, got, tc.want)
		}
	}
}

// TestIPToUint32AcceptsTheMappedSpelling covers the dual-stack form.
//
// A listener accepting on :: reports v4 clients as ::ffff:a.b.c.d. If that were
// rejected, a shun issued for a client seen on the dual-stack listener would
// fail with "only IPv4 is supported" while the same host on the v4 listener
// shunned fine.
func TestIPToUint32AcceptsTheMappedSpelling(t *testing.T) {
	mapped, err := ipToUint32("::ffff:203.0.113.10")
	if err != nil {
		t.Fatalf("a v4-mapped address was rejected: %v", err)
	}
	plain, err := ipToUint32("203.0.113.10")
	if err != nil {
		t.Fatalf("ipToUint32: %v", err)
	}
	if mapped != plain {
		t.Errorf("the mapped form gave %#08x and the plain form %#08x; the same "+
			"host must produce the same key however the listener spelled it",
			mapped, plain)
	}
}

// TestIPToUint32RejectsWhatItCannotEncode covers the failure paths.
//
// Returning 0 with no error would key every unencodable address to 0.0.0.0 and
// shun that instead.
func TestIPToUint32RejectsWhatItCannotEncode(t *testing.T) {
	for _, ip := range []string{
		"",
		"not-an-ip",
		"1.2.3",
		"1.2.3.4.5",
		"256.1.1.1",
		"1.2.3.4/24",  // CIDR, not an address
		"2001:db8::1", // real IPv6: the map is keyed by uint32
		"::1",
	} {
		if _, err := ipToUint32(ip); err == nil {
			t.Errorf("ipToUint32(%q) returned no error; an address that cannot be "+
				"encoded must not silently become a key", ip)
		}
	}
}

// TestUint32ToIPRoundTrips pins the inverse, which is what turns a map key back
// into something an operator can read.
func TestUint32ToIPRoundTrips(t *testing.T) {
	for _, ip := range []string{
		"0.0.0.0", "1.2.3.4", "127.0.0.1", "192.168.1.1",
		"203.0.113.10", "255.255.255.255",
	} {
		n, err := ipToUint32(ip)
		if err != nil {
			t.Fatalf("ipToUint32(%q): %v", ip, err)
		}
		if got := uint32ToIP(n).String(); got != ip {
			t.Errorf("round trip of %q gave %q; a shunned-IP listing that cannot "+
				"name the address it blocked is unactionable", ip, got)
		}
	}
}

// TestCloseResetsTheShunnedCount is the bookkeeping defect.
//
// close() tears down the objects, and the shunned_ips map goes with them, so
// afterwards nothing is shunned. It reset the map registry, the attach state and
// the load error, and left the counter alone -- so a detach and reattach (an
// interface change, a reload, a failed attach retried) carried the old number
// forward against an empty map.
//
// That number is not decorative: it is the security posture report's ShunnedIPs,
// the diagnostics screen's count, and the ActiveShunnedEntitiesTotal gauge. A
// metric that only ever drifts upward is worse than none, because it is what an
// operator checks to decide whether mitigation is working.
func TestCloseResetsTheShunnedCount(t *testing.T) {
	m := &EbpfManager{maps: map[string]*ebpf.Map{}}
	m.shunnedCount.Store(42)

	m.close()

	if got := m.shunnedCount.Load(); got != 0 {
		t.Errorf("after close the manager still reports %d shunned IPs.\n"+
			"The map they were in was destroyed by this call, so the true count is "+
			"zero; the posture report and the ActiveShunnedEntitiesTotal gauge read "+
			"this value and would keep claiming mitigation that is not in place.",
			got)
	}
}

// TestCloseIsIdempotent covers the documented contract.
func TestCloseIsIdempotent(t *testing.T) {
	m := &EbpfManager{maps: map[string]*ebpf.Map{}}
	m.close()
	m.close() // must not panic on already-cleared state

	if m.attached || m.loadErr != "" || m.attachMode != "" || len(m.maps) != 0 {
		t.Error("close left state behind on the second call")
	}
}
