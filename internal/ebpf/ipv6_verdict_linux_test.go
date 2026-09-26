// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"encoding/binary"
	"net"
	"slices"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Both programs used to pass every IPv6 packet untouched: no shun, no limit, no
// management gate. On a dual-stack host an attacker only had to use IPv6, and
// the management allowlist -- which promises that an unlisted address cannot
// reach the dashboard at all -- stopped at IPv4. These hold the IPv6 paths to
// the verdicts the IPv4 tests hold the IPv4 paths to.

// IPv6 next-header values (RFC 8200 and the IANA registry).
const (
	nhHopByHop = 0
	nhTCP      = 6
	nhFragment = 44
	nhICMPv6   = 58
	nhDestOpts = 60
)

// ipv6Frame is an Ethernet/IPv6 frame from src whose fixed header names next
// and carries payload: any extension headers, already chained, then the
// transport header.
func ipv6Frame(src net.IP, next byte, payload []byte) []byte {
	frame := make([]byte, 14+40+len(payload))
	binary.BigEndian.PutUint16(frame[12:], 0x86DD) // ETH_P_IPV6
	ip6 := frame[14:]
	ip6[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip6[4:], uint16(len(payload)))
	ip6[6] = next
	ip6[7] = 64 // hop limit
	copy(ip6[8:24], src.To16())
	copy(ip6[24:40], net.ParseIP("2001:db8:ffff::1").To16())
	copy(ip6[40:], payload)
	return frame
}

func tcp6(dport uint16, flags byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], 40000)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12] = 5 << 4
	h[13] = flags
	return h
}

// extHeader is an extension header of 8*(lenField+1) bytes naming next.
func extHeader(next, lenField byte) []byte {
	h := make([]byte, 8*(int(lenField)+1))
	h[0], h[1] = next, lenField
	return h
}

// fragHeader is a Fragment header naming next, at offset 8-byte units.
func fragHeader(next byte, offset uint16, more bool) []byte {
	h := make([]byte, 8)
	h[0] = next
	field := offset << 3
	if more {
		field |= 1
	}
	binary.BigEndian.PutUint16(h[2:], field)
	return h
}

func ipv6TCP(src net.IP, dport uint16, flags byte) []byte {
	return ipv6Frame(src, nhTCP, tcp6(dport, flags))
}

func mgmtAllowlistConfigV6() *gateonv1.EbpfConfig {
	cfg := mgmtAllowlistConfig()
	cfg.MgmtWhitelistIps = append(cfg.MgmtWhitelistIps, "2001:db8:a::40")
	return cfg
}

var (
	v6Admin    = net.ParseIP("2001:db8:a::40")
	v6Stranger = net.ParseIP("2001:db8:bad::1")
)

// TestIPv6CannotBypassAnIPv4OnlyAllowlist is the bypass. With only IPv4
// addresses listed, an IPv6 stranger reached the management port, because
// neither program looked at IPv6. An address family with nothing listed is
// closed, not open.
func TestIPv6CannotBypassAnIPv4OnlyAllowlist(t *testing.T) {
	_, coll := loadedManager(t, mgmtAllowlistConfig())
	for _, g := range []struct {
		prog string
		drop uint32
	}{{xdpProgName, xdpDrop}, {tcProgName, tcActShot}} {
		if v := verdict(t, coll.Programs[g.prog], ipv6TCP(v6Stranger, 8443, tcpSYN), 1); v != g.drop {
			t.Errorf("%s: an IPv6 stranger reached the management port past an IPv4-only allowlist "+
				"(verdict %d, want %d)", g.prog, v, g.drop)
		}
	}
}

// TestIPv6ManagementGates walks the header shapes past every gate. The ones
// that carry the property: a header the parser does not walk is dropped for an
// unlisted source while a gate is on, because it might hide the management
// port; and MLD and neighbour discovery always pass, because without them IPv6
// stops working at all.
func TestIPv6ManagementGates(t *testing.T) {
	gates := []struct {
		name       string
		prog       string
		cfg        func() *gateonv1.EbpfConfig
		listed     bool // whether v6Admin is on the allowlist
		drop, pass uint32
	}{
		{"XDP allowlist", xdpProgName, mgmtAllowlistConfigV6, true, xdpDrop, xdpPass},
		{"XDP port knocking", xdpProgName, knockingConfig, false, xdpDrop, xdpPass},
		{"TC allowlist", tcProgName, mgmtAllowlistConfigV6, true, tcActShot, tcActOK},
	}
	mld := ipv6Frame(v6Stranger, nhHopByHop, append(extHeader(nhICMPv6, 0), 143, 0, 0, 0, 0, 0, 0, 0))
	solicit := ipv6Frame(v6Stranger, nhICMPv6, append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, make([]byte, 16)...))
	for _, g := range gates {
		t.Run(g.name, func(t *testing.T) {
			_, coll := loadedManager(t, g.cfg())
			prog := coll.Programs[g.prog]
			cases := []struct {
				name string
				pkt  []byte
				want uint32
			}{
				{"stranger to the management port", ipv6TCP(v6Stranger, 8443, tcpSYN), g.drop},
				{"stranger to another port", ipv6TCP(v6Stranger, 443, tcpSYN), g.pass},
				{"stranger behind a Hop-by-Hop header", ipv6Frame(v6Stranger, nhHopByHop,
					append(extHeader(nhTCP, 0), tcp6(8443, tcpSYN)...)), g.drop},
				{"stranger's first fragment", ipv6Frame(v6Stranger, nhFragment,
					append(fragHeader(nhTCP, 0, true), tcp6(8443, tcpSYN)...)), g.drop},
				// Its payload looks like a TCP header for the management port, so
				// reading ports from a later fragment would drop it.
				{"stranger's later fragment", ipv6Frame(v6Stranger, nhFragment,
					append(fragHeader(nhTCP, 1, false), tcp6(8443, tcpSYN)...)), g.pass},
				{"stranger behind a header the parser does not walk", ipv6Frame(v6Stranger, nhDestOpts,
					append(extHeader(nhTCP, 0), tcp6(443, tcpSYN)...)), g.drop},
				{"MLD report", mld, g.pass},
				{"neighbour solicitation", solicit, g.pass},
			}
			if g.listed {
				cases = append(cases,
					struct {
						name string
						pkt  []byte
						want uint32
					}{"listed address to the management port", ipv6TCP(v6Admin, 8443, tcpSYN), g.pass},
					struct {
						name string
						pkt  []byte
						want uint32
					}{"listed address behind an unwalked header", ipv6Frame(v6Admin, nhDestOpts,
						append(extHeader(nhTCP, 0), tcp6(8443, tcpSYN)...)), g.pass})
			}
			for _, c := range cases {
				if v := verdict(t, prog, c.pkt, 1); v != c.want {
					t.Errorf("%s: verdict %d, want %d", c.name, v, c.want)
				}
			}
		})
	}
}

// TestIPv6UnwalkedHeaderPassesWithNoGate: failing closed on a header the parser
// does not walk is the gate's rule, not the program's. With no gate on, such a
// packet is ordinary traffic.
func TestIPv6UnwalkedHeaderPassesWithNoGate(t *testing.T) {
	_, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true, MgmtPort: 8443})
	pkt := ipv6Frame(v6Stranger, nhDestOpts, append(extHeader(nhTCP, 0), tcp6(8443, tcpSYN)...))
	if v := verdict(t, coll.Programs[xdpProgName], pkt, 1); v != xdpPass {
		t.Errorf("XDP dropped it (verdict %d) with no gate on", v)
	}
	if v := verdict(t, coll.Programs[tcProgName], pkt, 1); v != tcActOK {
		t.Errorf("TC dropped it (verdict %d) with no gate on", v)
	}
}

// TestIPv6ShunCoversTheSlash64: shunning one IPv6 address has to stop the
// attacker's next address in the same /64, and nothing outside it.
func TestIPv6ShunCoversTheSlash64(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	if err := m.ShunIP("2001:db8:1:2::10"); err != nil {
		t.Fatalf("ShunIP: %v", err)
	}
	sibling, neighbour := net.ParseIP("2001:db8:1:2::99"), net.ParseIP("2001:db8:1:3::10")
	for _, g := range []struct {
		prog       string
		drop, pass uint32
	}{{xdpProgName, xdpDrop, xdpPass}, {tcProgName, tcActShot, tcActOK}} {
		if v := verdict(t, coll.Programs[g.prog], ipv6TCP(sibling, 443, tcpACK), 1); v != g.drop {
			t.Errorf("%s: another address in the shunned /64 got verdict %d, want %d", g.prog, v, g.drop)
		}
		if v := verdict(t, coll.Programs[g.prog], ipv6TCP(neighbour, 443, tcpACK), 1); v != g.pass {
			t.Errorf("%s: an address in the next /64 got verdict %d, want %d", g.prog, v, g.pass)
		}
	}
	if err := m.UnshunIP("2001:db8:1:2::77"); err != nil {
		t.Fatalf("UnshunIP of another address in the /64: %v", err)
	}
	if v := verdict(t, coll.Programs[xdpProgName], ipv6TCP(sibling, 443, tcpACK), 1); v != xdpPass {
		t.Errorf("after the unshun the /64 still gets verdict %d", v)
	}
}

// TestIPv6RateLimitSharesABucketPerSlash64: a flood spread across a /64 is one
// flood.
func TestIPv6RateLimitSharesABucketPerSlash64(t *testing.T) {
	_, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpRateLimit: true})
	first, second := net.ParseIP("2001:db8:5::1"), net.ParseIP("2001:db8:5::2")
	other := net.ParseIP("2001:db8:6::1")
	for _, g := range []struct {
		prog       string
		drop, pass uint32
	}{{xdpProgName, xdpDrop, xdpPass}, {tcProgName, tcActShot, tcActOK}} {
		if v := verdict(t, coll.Programs[g.prog], ipv6TCP(first, 443, tcpACK), 64); v != g.pass {
			t.Fatalf("%s: the 64th packet of a first burst got verdict %d, want %d", g.prog, v, g.pass)
		}
		if v := verdict(t, coll.Programs[g.prog], ipv6TCP(second, 443, tcpACK), 64); v != g.drop {
			t.Errorf("%s: a second address in the same /64 got a fresh burst (last verdict %d, want %d)",
				g.prog, v, g.drop)
		}
		if v := verdict(t, coll.Programs[g.prog], ipv6TCP(other, 443, tcpACK), 1); v != g.pass {
			t.Errorf("%s: another /64 was limited too (verdict %d)", g.prog, v)
		}
		first, second, other = net.ParseIP("2001:db8:7::1"), net.ParseIP("2001:db8:7::2"), net.ParseIP("2001:db8:8::1")
	}
}

func TestIPv6SYNFloodGuard(t *testing.T) {
	_, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	prog := coll.Programs[xdpProgName]
	syn := ipv6TCP(net.ParseIP("2001:db8:9::1"), 443, tcpSYN)
	if v := verdict(t, prog, syn, 6); v != xdpPass {
		t.Fatalf("the 6th SYN from one IPv6 client got verdict %d, want XDP_PASS", v)
	}
	if v := verdict(t, prog, syn, 512); v != xdpDrop {
		t.Fatalf("512 more SYNs with no handshake completing were all passed (last verdict %d)", v)
	}
}

// TestIPv6PortKnockOpensTheManagementPort: knocking works over IPv6, and opens
// the port for the address that knocked -- not for the rest of its /64.
func TestIPv6PortKnockOpensTheManagementPort(t *testing.T) {
	_, coll := loadedManager(t, knockingConfig())
	prog := coll.Programs[xdpProgName]
	knocker, bystander := net.ParseIP("2001:db8:c::7"), net.ParseIP("2001:db8:c::8")

	for _, port := range []uint16{7000, 8000, 9000} {
		if v := verdict(t, prog, ipv6TCP(knocker, port, tcpSYN), 1); v != xdpDrop {
			t.Fatalf("knock on %d got verdict %d, want XDP_DROP", port, v)
		}
	}
	if v := verdict(t, prog, ipv6TCP(knocker, 8443, tcpSYN), 1); v != xdpPass {
		t.Errorf("after the full sequence the knocker still cannot reach the port (verdict %d)", v)
	}
	if v := verdict(t, prog, ipv6TCP(bystander, 8443, tcpSYN), 1); v != xdpDrop {
		t.Errorf("the knock opened the port for another address in the /64 (verdict %d)", v)
	}
}

func TestIPv6TopTalkersIncludeIPv6(t *testing.T) {
	m, coll := loadedManager(t, &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true})
	verdict(t, coll.Programs[xdpProgName], ipv6TCP(net.ParseIP("2001:db8:77::1"), 443, tcpACK), 3)
	top, err := m.GetTopIPs(10)
	if err != nil {
		t.Fatalf("GetTopIPs: %v", err)
	}
	if !slices.ContainsFunc(top, func(s IPStat) bool { return s.IP == "2001:db8:77::1" && s.Count == 3 }) {
		t.Errorf("GetTopIPs = %+v, want 2001:db8:77::1 with 3 packets", top)
	}
}

// TestSeedManagementWhitelistClosesAFamilyWithNoEntry: an IPv6-only allowlist
// switches the gate on, and then IPv4 -- with nothing listed -- is closed too.
// One gate for both families is what stops either being a way around it.
func TestSeedManagementWhitelistClosesAFamilyWithNoEntry(t *testing.T) {
	_, coll := loadedManager(t, &gateonv1.EbpfConfig{
		Enabled: true, XdpIpShunning: true, EnableMgmtWhitelist: true,
		MgmtWhitelistIps: []string{"2001:db8:a::40"}, MgmtPort: 8443,
	})
	prog := coll.Programs[xdpProgName]
	if v := verdict(t, prog, ipv6TCP(v6Admin, 8443, tcpSYN), 1); v != xdpPass {
		t.Errorf("the one listed IPv6 address cannot reach the management port (verdict %d)", v)
	}
	if v := verdict(t, prog, ipv4TCP(net.IPv4(203, 0, 113, 50), 8443, tcpSYN), 1); v != xdpDrop {
		t.Errorf("with only IPv6 listed an IPv4 stranger reached the management port (verdict %d)", v)
	}
}
