// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// These run the compiled program with BPF_PROG_TEST_RUN, so what they assert is
// the verdict a real packet would get. A Go-side map update returning nil says
// nothing about whether the address it named is the one the kernel checks --
// which is the whole failure mode both defects below had.

// xdpTX is XDP_TX from linux/bpf.h: put the frame back out the interface it
// arrived on. There is no fallback path from it; a frame sent with an
// unroutable destination is destroyed.
const xdpTX = 3

// TestXDPManagementWhitelistRevokesWhatConfigRemoved is the revocation defect.
//
// UpdateManagementWhitelist only ever added. Deleting an administrator's address
// in the dashboard left the entry in mgmt_whitelist until the program was torn
// down, so the revoked address kept kernel-level access to the management port
// across every config save and every reload -- the one place where removing an
// entry has to mean something.
//
// The second half of the test is why a blunt "clear the map and refill" is not
// the fix: the XDP program writes into this same map itself when a source
// completes the port-knock sequence, and that entry is what is holding the
// operator's own session open. Wiping it on an unrelated config save would lock
// out whoever is doing the saving.
func TestXDPManagementWhitelistRevokesWhatConfigRemoved(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{
		Enabled:          true,
		XdpIpShunning:    true,
		EnableKnocking:   true,
		MgmtPort:         8443,
		KnockingSequence: []int32{7000, 8000, 9000},
	})
	prog := coll.Programs[xdpProgName]

	admin := net.IPv4(198, 51, 100, 40)   // whitelisted by configuration
	knocker := net.IPv4(198, 51, 100, 41) // whitelisted by completing the knock

	if err := m.UpdateManagementWhitelist([]string{"198.51.100.40"}); err != nil {
		t.Fatalf("UpdateManagementWhitelist: %v", err)
	}
	if v := verdict(t, prog, ipv4TCP(admin, 8443, tcpSYN), 1); v != xdpPass {
		t.Fatalf("a configured whitelist entry does not reach the management port "+
			"(verdict %d, want XDP_PASS %d)", v, xdpPass)
	}

	// The knocker earns its entry from inside the kernel, not from config.
	for _, port := range []uint16{7000, 8000, 9000} {
		verdict(t, prog, ipv4TCP(knocker, port, tcpSYN), 1)
	}
	if v := verdict(t, prog, ipv4TCP(knocker, 8443, tcpSYN), 1); v != xdpPass {
		t.Fatalf("the knock sequence did not open the management port (verdict %d); the rest "+
			"of this test has nothing to protect", v)
	}

	// The operator removes the administrator from the dashboard.
	if err := m.UpdateManagementWhitelist(nil); err != nil {
		t.Fatalf("UpdateManagementWhitelist (revoking): %v", err)
	}

	if v := verdict(t, prog, ipv4TCP(admin, 8443, tcpSYN), 1); v != xdpDrop {
		t.Errorf("after being removed from the configured whitelist, 198.51.100.40 still reaches "+
			"the management port (verdict %d, want XDP_DROP %d).\n"+
			"The update only ever added entries, so a revoked administrator keeps kernel-level "+
			"access to the management port until the program is torn down.", v, xdpDrop)
	}
	if v := verdict(t, prog, ipv4TCP(knocker, 8443, tcpSYN), 1); v != xdpPass {
		t.Errorf("saving the whitelist revoked 198.51.100.41, which was let in by completing the "+
			"port-knock sequence, not by configuration (verdict %d, want XDP_PASS %d).\n"+
			"Knock-granted entries live in the same map and must survive an unrelated config "+
			"save, or saving settings locks out the operator doing it.", v, xdpPass)
	}
}

// TestXDPManagementWhitelistReinstatesAcrossUpdates: an address that stays in
// the configured set across an update must keep working. Deleting then re-adding
// within one call must not leave a gap, and must not delete something the same
// call re-installs.
func TestXDPManagementWhitelistReinstatesAcrossUpdates(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{
		Enabled: true, XdpIpShunning: true, EnableKnocking: true,
		MgmtPort: 8443, KnockingSequence: []int32{7000},
	})
	prog := coll.Programs[xdpProgName]
	kept := net.IPv4(198, 51, 100, 42)

	if err := m.UpdateManagementWhitelist([]string{"198.51.100.42", "198.51.100.43"}); err != nil {
		t.Fatalf("UpdateManagementWhitelist: %v", err)
	}
	if err := m.UpdateManagementWhitelist([]string{"198.51.100.42"}); err != nil {
		t.Fatalf("UpdateManagementWhitelist (second): %v", err)
	}

	if v := verdict(t, prog, ipv4TCP(kept, 8443, tcpSYN), 1); v != xdpPass {
		t.Errorf("198.51.100.42 was in both the old and the new configured set and no longer "+
			"reaches the management port (verdict %d, want XDP_PASS %d): the delta deleted an "+
			"address it should have kept", v, xdpPass)
	}
	if v := verdict(t, prog, ipv4TCP(net.IPv4(198, 51, 100, 43), 8443, tcpSYN), 1); v != xdpDrop {
		t.Errorf("198.51.100.43 was dropped from the configured set and still reaches the "+
			"management port (verdict %d, want XDP_DROP %d)", v, xdpDrop)
	}
}

// TestXDPDoesNotTransmitToAnUnaddressableBackend is the blackhole defect at the
// kernel.
//
// The load-balancing branch rewrote iph->daddr and eth->h_dest from the stored
// backend and returned XDP_TX. With the all-zero MAC the Go side installed, that
// put the frame back on the wire addressed to 00:00:00:00:00:00 -- and XDP_TX
// has no fallback, so the packet never reaches the stack and is simply gone.
// The entry is written here by hand because the Go side now refuses to create
// one; this is the kernel-side half of the same refusal, for an entry written by
// anything else.
func TestXDPDoesNotTransmitToAnUnaddressableBackend(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	prog := coll.Programs[xdpProgName]

	// struct backend in bpf/xdp_rate_limit.c is __u32 + __u8[6], which the
	// kernel map rounds up to 12 bytes. The Go side's own 10-byte mirror could
	// not marshal into it at all, so every backend write it made failed -- with
	// the error discarded -- and the count was raised anyway: the XDP path then
	// read an all-zero entry and XDP_TX'd to 0.0.0.0 via 00:00:00:00:00:00.
	type backend struct {
		IP      uint32
		EthAddr [6]uint8
		_       [2]uint8
	}
	backendIP, err := ipToUint32("10.20.30.40")
	if err != nil {
		t.Fatalf("ipToUint32: %v", err)
	}
	// An entry with no destination MAC: exactly what used to be installed.
	if err := m.maps["lb_backends"].Update(uint32(0), backend{IP: backendIP}, ebpf.UpdateAny); err != nil {
		t.Fatalf("seeding lb_backends: %v", err)
	}
	if err := m.maps["lb_backends_count"].Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		t.Fatalf("seeding lb_backends_count: %v", err)
	}

	pkt := ipv4TCP(net.IPv4(198, 51, 100, 50), 443, tcpACK)
	out := make([]byte, len(pkt)+256)
	opts := &ebpf.RunOptions{Data: pkt, DataOut: out}
	v, err := prog.Run(opts)
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}

	if v == xdpTX {
		t.Fatalf("a packet was XDP_TX'd to a backend with no destination MAC.\n"+
			"XDP_TX puts the frame straight back on the wire; addressed to "+
			"00:00:00:00:00:00, with the IPv4 and L4 checksums left stale, it is silently "+
			"destroyed and never reaches the stack. Want XDP_PASS (%d).", xdpPass)
	}
	if v != xdpPass {
		t.Fatalf("verdict %d, want XDP_PASS (%d): an unaddressable backend must leave the "+
			"packet on the normal path, not change its fate at all", v, xdpPass)
	}
	if len(opts.DataOut) >= 14+20 {
		dst := opts.DataOut[14+16 : 14+20]
		if net.IP(dst).String() != "10.0.0.1" {
			t.Errorf("the destination address was rewritten to %s even though the packet was "+
				"passed; a rewritten header with no redirect is a corrupted packet",
				net.IP(dst))
		}
		for i, b := range opts.DataOut[0:6] {
			if b != pkt[i] {
				t.Errorf("the destination MAC was rewritten on a packet that was passed: % x",
					opts.DataOut[0:6])
				break
			}
		}
	}
}

// TestUpdateLoadBalancerBackendsForcesTheKernelCountToZero: the refusal has to
// take effect in the kernel, not only in the returned error. Whatever was
// installed before must stop being balanced, because the XDP branch is gated on
// this counter and nothing else.
func TestUpdateLoadBalancerBackendsForcesTheKernelCountToZero(t *testing.T) {
	m, _ := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpLoadBalancing: true})

	if err := m.maps["lb_backends_count"].Update(uint32(0), uint32(4), ebpf.UpdateAny); err != nil {
		t.Fatalf("seeding lb_backends_count: %v", err)
	}

	if err := m.UpdateLoadBalancerBackends([]string{"10.20.30.40"}); err == nil {
		t.Fatal("installing a backend with no resolvable MAC was accepted")
	}

	var count uint32
	if err := m.maps["lb_backends_count"].Lookup(uint32(0), &count); err != nil {
		t.Fatalf("reading lb_backends_count: %v", err)
	}
	if count != 0 {
		t.Errorf("lb_backends_count = %d after a refused update, want 0.\n"+
			"The XDP branch balances whenever this counter is non-zero, so a refusal that "+
			"leaves it set keeps redirecting to whatever was installed before.", count)
	}
}
