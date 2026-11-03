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

// CVE-2026-98432 is a use-after-free in the kernel's IPv4 TCP handshake: the IP
// options a SYN carries are saved on the request socket, handed to the child
// without a copy, and freed while a retransmitted SYN on another CPU still
// builds a SYN-ACK from them. It fires before accept(), so nothing above the
// kernel -- the WAF included -- ever sees the request. Only a hook in front of
// the TCP stack can refuse the trigger, and these check that both do.

// dropReasonIPOptionsSYN mirrors DROP_REASON_IP_OPTIONS_SYN in the C program.
const dropReasonIPOptionsSYN = 6

// optionShapes is the trigger in each form the stack would still deliver: the
// options the exploit uses, NOP padding the kernel saves just the same, and a
// first fragment too short to show the flags -- reassembly hands the TCP stack
// a whole SYN with its options, so an unreadable flags byte cannot be a pass.
func optionShapes(src net.IP) []struct {
	name string
	pkt  []byte
} {
	return []struct {
		name string
		pkt  []byte
	}{
		{"record route", withIPOption(ipv4TCPWithOptions(src, 443, tcpSYN, 2), 0x07)},
		{"timestamp", withIPOption(ipv4TCPWithOptions(src, 443, tcpSYN, 2), 0x44)},
		{"NOP padding", ipv4TCPWithOptions(src, 443, tcpSYN, 1)},
		{"maximum options, IHL 15", ipv4TCPWithOptions(src, 443, tcpSYN, 10)},
		{"first fragment with options, flags cut off", ipv4FirstFragmentWithOptions(src, 443)},
	}
}

// withIPOption writes an option of kind into the first option bytes of pkt,
// with a length that fills the option area, the way RR and TS are laid out.
func withIPOption(pkt []byte, kind byte) []byte {
	ip := pkt[14:]
	optLen := int(ip[0]&0x0f)*4 - 20
	ip[20] = kind
	ip[21] = byte(optLen)
	ip[22] = 4 // pointer: first slot
	for i := 23; i < 20+optLen; i++ {
		ip[i] = 0
	}
	return pkt
}

// ipv4FirstFragmentWithOptions is the first fragment of a SYN to dport with
// one IP option word, cut after 8 bytes of TCP header: ports, no flags.
func ipv4FirstFragmentWithOptions(src net.IP, dport uint16) []byte {
	const ihl = 6
	pkt := make([]byte, 14+ihl*4+8)
	binary.BigEndian.PutUint16(pkt[12:], 0x0800)
	ip := pkt[14:]
	ip[0] = 0x40 | ihl
	binary.BigEndian.PutUint16(ip[2:], ihl*4+8)
	binary.BigEndian.PutUint16(ip[6:], 0x2000) // MF, offset 0
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src.To4())
	copy(ip[16:20], net.IPv4(10, 0, 0, 1).To4())
	for i := 20; i < ihl*4; i++ {
		ip[i] = 0x01
	}
	binary.BigEndian.PutUint16(ip[ihl*4:], 40000)
	binary.BigEndian.PutUint16(ip[ihl*4+2:], dport)
	return pkt
}

var ipOptionHooks = []struct {
	name       string
	prog       string
	drop, pass uint32
}{
	{"XDP", xdpProgName, xdpDrop, xdpPass},
	{"TC", tcProgName, tcActShot, tcActOK},
}

// TestIPOptionSYNIsDroppedOnFirstPacket: the race needs only a SYN and its
// retransmission, so a guard that waits for a burst is too late. Every shape is
// dropped on the first packet, with no feature switched on, on both hooks.
func TestIPOptionSYNIsDroppedOnFirstPacket(t *testing.T) {
	for _, h := range ipOptionHooks {
		t.Run(h.name, func(t *testing.T) {
			m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true})
			prog := coll.Programs[h.prog]
			for _, s := range optionShapes(net.IPv4(198, 51, 100, 80)) {
				if v := verdict(t, prog, s.pkt, 1); v != h.drop {
					t.Errorf("%s: a SYN carrying IPv4 options got verdict %d, want %d: "+
						"the CVE-2026-98432 trigger reached the TCP stack", s.name, v, h.drop)
				}
			}
			if got := dropCount(t, m, dropReasonIPOptionsSYN); got < uint64(len(optionShapes(nil))) {
				t.Errorf("ip_options_syn counter is %d after %d drops; the dashboard would show none",
					got, len(optionShapes(nil)))
			}
		})
	}
}

// TestIPOptionDropLeavesOrdinaryTrafficAlone: the control. A SYN without
// options, and established traffic that does carry them, are untouched: the
// rule is the handshake trigger, not every packet with an option.
func TestIPOptionDropLeavesOrdinaryTrafficAlone(t *testing.T) {
	src := net.IPv4(198, 51, 100, 60)
	shapes := []struct {
		name string
		pkt  []byte
	}{
		{"SYN without options", ipv4TCP(src, 443, tcpSYN)},
		{"ACK with options", ipv4TCPWithOptions(src, 443, tcpACK, 1)},
		{"SYN-ACK with options", ipv4TCPWithOptions(src, 443, tcpSYN|tcpACK, 1)},
	}
	for _, h := range ipOptionHooks {
		t.Run(h.name, func(t *testing.T) {
			_, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true})
			for _, s := range shapes {
				if v := verdict(t, coll.Programs[h.prog], s.pkt, 1); v != h.pass {
					t.Errorf("%s got verdict %d, want %d", s.name, v, h.pass)
				}
			}
		})
	}
}

// TestIPOptionSYNIsDroppedForAllowlistedSources: the allowlist exists so an
// operator cannot lock themselves out, and a kernel bug is not a lockout. A
// listed address can be spoofed in a SYN, which needs no reply to land.
func TestIPOptionSYNIsDroppedForAllowlistedSources(t *testing.T) {
	src := net.IPv4(198, 51, 100, 40) // listed by mgmtAllowlistConfig
	pkt := withIPOption(ipv4TCPWithOptions(src, 8443, tcpSYN, 2), 0x07)
	for _, h := range ipOptionHooks {
		t.Run(h.name, func(t *testing.T) {
			_, coll := loadedManager(t, mgmtAllowlistConfig())
			if v := verdict(t, coll.Programs[h.prog], pkt, 1); v != h.drop {
				t.Errorf("an allowlisted source's SYN with IP options got verdict %d, want %d", v, h.drop)
			}
		})
	}
}

func dropCount(t *testing.T, m *EbpfManager, reason uint32) uint64 {
	t.Helper()
	m.mu.RLock()
	stats := m.maps["drop_stats"]
	m.mu.RUnlock()
	var per []uint64
	if err := stats.Lookup(reason, &per); err != nil {
		t.Fatalf("read drop_stats[%d]: %v", reason, err)
	}
	var total uint64
	for _, v := range per {
		total += v
	}
	return total
}
