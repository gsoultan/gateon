// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The management-port gate and the SYN-flood guard read the TCP header, and
// both used to find it a fixed 20 bytes past the start of the IPv4 header. That
// is only where it is when the header has no options; IHL says where it really
// is. One option word moved every port-based decision onto bytes the sender
// chose, and a first fragment cut short of a whole TCP header skipped the
// checks entirely -- while the kernel's reassembly and IP stack delivered both
// to the management port as normal.

// ipv4FirstFragment is the first fragment of a TCP segment to dport, cut after
// 8 bytes of TCP header: the least a first fragment carries, because fragment
// offsets count in 8-byte units. The ports are in it; the flags are not.
func ipv4FirstFragment(src net.IP, dport uint16) []byte {
	pkt := ipv4Fragment(src, 0x2000, 8) // MF set, offset 0
	binary.BigEndian.PutUint16(pkt[14+20:], 40000)
	binary.BigEndian.PutUint16(pkt[14+22:], dport)
	return pkt
}

// ipv4LaterFragment is a non-first fragment whose payload happens to hold dport
// where a TCP header would keep its destination port. It carries no TCP header,
// so nothing port-shaped may be read from it.
func ipv4LaterFragment(src net.IP, dport uint16) []byte {
	pkt := ipv4Fragment(src, 0x0001, 20) // offset 8 bytes, last fragment
	binary.BigEndian.PutUint16(pkt[14+22:], dport)
	return pkt
}

func ipv4Fragment(src net.IP, fragField uint16, payload int) []byte {
	pkt := make([]byte, 14+20+payload)
	binary.BigEndian.PutUint16(pkt[12:], 0x0800) // ETH_P_IP
	ip := pkt[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+payload))
	binary.BigEndian.PutUint16(ip[6:], fragField)
	ip[8] = 64 // TTL
	ip[9] = 6  // IPPROTO_TCP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 1).To4())
	return pkt
}

func knockingConfig() *gateonv1.EbpfConfig {
	return &gateonv1.EbpfConfig{
		Enabled:          true,
		XdpIpShunning:    true,
		EnableKnocking:   true,
		MgmtPort:         8443,
		KnockingSequence: []int32{7000, 8000, 9000},
	}
}

// mgmtGates is every kernel check that closes the management port to a source,
// with the verdicts its hook uses.
var mgmtGates = []struct {
	name       string
	prog       string
	cfg        func() *gateonv1.EbpfConfig
	drop, pass uint32
}{
	{"XDP allowlist", xdpProgName, mgmtAllowlistConfig, xdpDrop, xdpPass},
	{"XDP port knocking", xdpProgName, knockingConfig, xdpDrop, xdpPass},
	{"TC allowlist", tcProgName, mgmtAllowlistConfig, tcActShot, tcActOK},
}

// TestManagementGatesFindTheTCPHeaderByIHL: however the header is shaped, a
// stranger's SYN to the management port is dropped. The first shape is the
// control -- the gate works at all -- so the others can only fail on the shape.
func TestManagementGatesFindTheTCPHeaderByIHL(t *testing.T) {
	stranger := net.IPv4(203, 0, 113, 60)
	shapes := []struct {
		name string
		pkt  []byte
	}{
		{"no options", ipv4TCP(stranger, 8443, tcpSYN)},
		{"one option word", ipv4TCPWithOptions(stranger, 8443, tcpSYN, 1)},
		{"maximum options, IHL 15", ipv4TCPWithOptions(stranger, 8443, tcpSYN, 10)},
		{"first fragment, 8 bytes of TCP", ipv4FirstFragment(stranger, 8443)},
	}
	for _, g := range mgmtGates {
		t.Run(g.name, func(t *testing.T) {
			_, coll := loadedManager(t, g.cfg())
			prog := coll.Programs[g.prog]
			for _, s := range shapes {
				if v := verdict(t, prog, s.pkt, 1); v != g.drop {
					t.Errorf("%s: a stranger's SYN to the management port got verdict %d, want %d: "+
						"the gate read its port from the wrong bytes and let it through", s.name, v, g.drop)
				}
			}
		})
	}
}

// TestManagementGatesReadNoPortFromALaterFragment: a later fragment has no TCP
// header, and reading its payload as one drops traffic by coincidence -- or,
// under port knocking, lets payload bytes count as knocks. It cannot reach the
// port without its first fragment, which the gate does check.
func TestManagementGatesReadNoPortFromALaterFragment(t *testing.T) {
	pkt := ipv4LaterFragment(net.IPv4(203, 0, 113, 61), 8443)
	for _, g := range mgmtGates {
		t.Run(g.name, func(t *testing.T) {
			_, coll := loadedManager(t, g.cfg())
			if v := verdict(t, coll.Programs[g.prog], pkt, 1); v != g.pass {
				t.Errorf("a later fragment whose payload holds 8443 got verdict %d, want %d: "+
					"payload bytes were read as a destination port", v, g.pass)
			}
		})
	}
}

// TestXDPSYNFloodGuardSeesPastIPOptions: the guard reads the SYN flag from the
// TCP header. At a fixed offset, one option word put the flags on a byte of the
// acknowledgement number, and a SYN flood carrying an option was never counted.
func TestXDPSYNFloodGuardSeesPastIPOptions(t *testing.T) {
	_, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	prog := coll.Programs[xdpProgName]
	syn := ipv4TCPWithOptions(net.IPv4(198, 51, 100, 31), 443, tcpSYN, 1)

	if v := verdict(t, prog, syn, 6); v != xdpPass {
		t.Fatalf("the 6th SYN from one client with no ACK in between got verdict %d, want XDP_PASS %d", v, xdpPass)
	}
	if v := verdict(t, prog, syn, 512); v != xdpDrop {
		t.Fatalf("512 more SYNs carrying an IP option were all passed (last verdict %d); "+
			"the guard read the flags from the wrong offset", v)
	}
}
