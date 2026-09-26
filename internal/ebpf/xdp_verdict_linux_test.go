// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// These feed hand-built frames through the compiled programs with
// BPF_PROG_TEST_RUN, so what they check is the verdict the kernel would give a
// real packet -- not that a map update returned nil, which is all the Go side
// can see and which is satisfied just as well by a key that names the wrong
// host. Root is needed to load the object; without it they skip, exactly as
// the attach tests do.

// Verdicts: XDP_DROP / XDP_PASS from linux/bpf.h, TC_ACT_OK / TC_ACT_SHOT from
// linux/pkt_cls.h.
const (
	xdpDrop   = 1
	xdpPass   = 2
	tcActOK   = 0
	tcActShot = 2
)

const (
	tcpSYN = 0x02
	tcpACK = 0x10
)

// loadedManager loads the object into a fresh manager the way loadHook and
// commit do, minus the attach: maps registered, runtime config written into
// the kernel, and everything torn down when the test ends.
func loadedManager(t *testing.T, cfg *gateonv1.EbpfConfig) (*EbpfManager, *ebpf.Collection) {
	t.Helper()
	requireBPFCapabilities(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("memlock rlimit not raised (%v); continuing, as the loader does", err)
	}
	spec, err := loadGateon_ebpf()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("create collection (verifier rejected the program?): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := NewEbpfManager(cfg)
	m.commit(ctx, coll, closerFunc(func() error { return nil }), "test0", attachModeNative, "XDP")
	t.Cleanup(func() {
		cancel()
		m.close() // idempotent; makes teardown synchronous for the test
	})
	return m, coll
}

// ipv4TCP builds an Ethernet/IPv4/TCP frame from src to a fixed destination.
// Checksums stay zero: neither program verifies them and the test runner does
// not either.
func ipv4TCP(src net.IP, dport uint16, flags byte) []byte {
	return ipv4TCPWithOptions(src, dport, flags, 0)
}

// ipv4TCPWithOptions is ipv4TCP with optWords 4-byte words of IP options
// (NOPs) between the IPv4 and TCP headers, so IHL is 5+optWords.
func ipv4TCPWithOptions(src net.IP, dport uint16, flags byte, optWords int) []byte {
	ihl := 5 + optWords
	pkt := make([]byte, 14+ihl*4+20)
	binary.BigEndian.PutUint16(pkt[12:], 0x0800) // ETH_P_IP
	ip := pkt[14:]
	ip[0] = 0x40 | byte(ihl) // version 4
	binary.BigEndian.PutUint16(ip[2:], uint16(ihl*4+20))
	ip[8] = 64 // TTL
	ip[9] = 6  // IPPROTO_TCP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 1).To4())
	for i := 20; i < ihl*4; i++ {
		ip[i] = 0x01 // IPOPT_NOOP
	}
	tcp := ip[ihl*4:]
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 5 << 4 // data offset: 5 words
	tcp[13] = flags
	return pkt
}

// verdict runs the program repeat times on the same frame, back to back inside
// the kernel, and returns the verdict of the last run.
func verdict(t *testing.T, prog *ebpf.Program, pkt []byte, repeat uint32) uint32 {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt, Repeat: repeat})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	return ret
}

func dropped(t *testing.T, m *EbpfManager, reason string) uint64 {
	t.Helper()
	stats, err := m.GetMapStats()
	if err != nil {
		t.Fatalf("GetMapStats: %v", err)
	}
	return stats.DroppedPackets[reason]
}

// TestXDPShunDropsTheAddressThatWasShunned is the end-to-end check on the map
// key. The program compares the key against the source address exactly as it
// sits in the IPv4 header, so a shun must drop that host -- and only that host.
func TestXDPShunDropsTheAddressThatWasShunned(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	xdp, tc := coll.Programs[xdpProgName], coll.Programs[tcProgName]

	attacker := net.IPv4(203, 0, 113, 10)
	reversed := net.IPv4(10, 113, 0, 203) // the same four bytes, backwards

	if err := m.ShunIP("203.0.113.10"); err != nil {
		t.Fatalf("ShunIP: %v", err)
	}

	if v := verdict(t, xdp, ipv4TCP(attacker, 443, tcpACK), 1); v != xdpDrop {
		t.Errorf("XDP: a packet from the shunned address got verdict %d, want XDP_DROP (%d)", v, xdpDrop)
	}
	if n := dropped(t, m, "shunned_ip"); n != 1 {
		t.Errorf("shunned_ip drop counter = %d, want 1: the drop, if any, was not the shun", n)
	}
	if v := verdict(t, tc, ipv4TCP(attacker, 443, tcpACK), 1); v != tcActShot {
		t.Errorf("TC: a packet from the shunned address got verdict %d, want TC_ACT_SHOT (%d)", v, tcActShot)
	}
	if v := verdict(t, xdp, ipv4TCP(reversed, 443, tcpACK), 1); v != xdpPass {
		t.Errorf("XDP: a packet from 10.113.0.203, the byte-reversed spelling of the shunned "+
			"address, got verdict %d, want XDP_PASS: the shun landed on an unrelated host", v)
	}
}

// TestXDPTopIPsNamesTheRealSource covers the read side of the same key: what
// the dashboard's top-talkers list shows must be the address that sent the
// packets.
func TestXDPTopIPsNamesTheRealSource(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})

	verdict(t, coll.Programs[xdpProgName], ipv4TCP(net.IPv4(203, 0, 113, 77), 443, tcpACK), 1)

	top, err := m.GetTopIPs(10)
	if err != nil {
		t.Fatalf("GetTopIPs: %v", err)
	}
	if len(top) != 1 || top[0].IP != "203.0.113.77" {
		t.Errorf("GetTopIPs = %+v, want one entry for 203.0.113.77", top)
	}
}

// TestXDPRateLimitOffDoesNotDropBursts: with xdp_rate_limit unset, a client
// sending a burst -- which is what every TCP window is -- must not lose packets.
func TestXDPRateLimitOffDoesNotDropBursts(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	pkt := ipv4TCP(net.IPv4(198, 51, 100, 20), 443, tcpACK)

	if v := verdict(t, coll.Programs[xdpProgName], pkt, 64); v != xdpPass {
		t.Errorf("XDP: with xdp_rate_limit off, the 64th back-to-back packet from one client "+
			"got verdict %d, want XDP_PASS: the limiter runs regardless of the flag", v)
	}
	if v := verdict(t, coll.Programs[tcProgName], pkt, 64); v != tcActOK {
		t.Errorf("TC: with xdp_rate_limit off, the 64th back-to-back packet from one client "+
			"got verdict %d, want TC_ACT_OK: the limiter runs regardless of the flag", v)
	}
	if n := dropped(t, m, "rate_limited"); n != 0 {
		t.Errorf("rate_limited drop counter = %d with the limiter not requested, want 0", n)
	}
}

// TestXDPRateLimitOnAllowsABurstThenDrops: with the limiter on, a window-sized
// burst passes and a sustained flood does not.
func TestXDPRateLimitOnAllowsABurstThenDrops(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpRateLimit: true})
	prog := coll.Programs[xdpProgName]
	pkt := ipv4TCP(net.IPv4(198, 51, 100, 21), 443, tcpACK)

	if v := verdict(t, prog, pkt, 64); v != xdpPass {
		t.Fatalf("the 64th packet of a client's first burst got verdict %d, want XDP_PASS: "+
			"a limiter with no burst allowance drops the second segment of every window", v)
	}
	if v := verdict(t, prog, pkt, 4096); v != xdpDrop {
		t.Fatalf("4096 further packets in well under a millisecond were all passed (last verdict %d); "+
			"the limiter is not enforcing", v)
	}
	if n := dropped(t, m, "rate_limited"); n == 0 {
		t.Error("packets were dropped but the rate_limited counter did not move")
	}
}

// TestXDPParallelSYNsFromOneClientAreNotDropped: a browser opens several
// connections at once, so several SYNs arrive before any ACK. Only a source
// that keeps opening connections without ever completing one is a flood.
func TestXDPParallelSYNsFromOneClientAreNotDropped(t *testing.T) {
	_, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	prog := coll.Programs[xdpProgName]
	syn := ipv4TCP(net.IPv4(198, 51, 100, 30), 443, tcpSYN)

	if v := verdict(t, prog, syn, 6); v != xdpPass {
		t.Fatalf("the 6th SYN from one client with no ACK in between got verdict %d, want XDP_PASS", v)
	}
	if v := verdict(t, prog, syn, 512); v != xdpDrop {
		t.Fatalf("512 more SYNs from one source with no handshake completing were all passed "+
			"(last verdict %d); the SYN-burst guard is not enforcing", v)
	}
}

// TestXDPPortKnockOpensTheManagementPort walks the sequence the way an operator
// would. Before the sequence the port is closed; each knock is consumed; after
// the last knock the port opens for that source and stays closed for others.
func TestXDPPortKnockOpensTheManagementPort(t *testing.T) {
	_, coll := loadedManager(t, &gateonv1.EbpfConfig{
		Enabled:          true,
		XdpIpShunning:    true,
		EnableKnocking:   true,
		MgmtPort:         8443,
		KnockingSequence: []int32{7000, 8000, 9000},
	})
	prog := coll.Programs[xdpProgName]
	operator := net.IPv4(198, 51, 100, 7)
	bystander := net.IPv4(198, 51, 100, 8)

	if v := verdict(t, prog, ipv4TCP(operator, 8443, tcpSYN), 1); v != xdpDrop {
		t.Fatalf("management port reachable before any knock (verdict %d)", v)
	}
	for _, port := range []uint16{7000, 8000, 9000} {
		if v := verdict(t, prog, ipv4TCP(operator, port, tcpSYN), 1); v != xdpDrop {
			t.Fatalf("knock on %d got verdict %d, want XDP_DROP: a knock is consumed, never delivered", port, v)
		}
	}
	if v := verdict(t, prog, ipv4TCP(operator, 8443, tcpSYN), 1); v != xdpPass {
		t.Errorf("after the full knock sequence the management port is still closed to the "+
			"knocker (verdict %d, want XDP_PASS): the sequence can never complete", v)
	}
	if v := verdict(t, prog, ipv4TCP(bystander, 8443, tcpSYN), 1); v != xdpDrop {
		t.Errorf("one source's knock opened the management port for another (verdict %d)", v)
	}
}
