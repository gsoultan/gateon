// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// The verdict tests prove each program's decision with BPF_PROG_TEST_RUN and
// the attach tests prove the hooks attach, but neither drops a packet anybody
// sent. These do. Frames are injected on one end of a veth pair, the manager
// attaches to the other end the way Start does in production, and a UDP socket
// bound behind it reports what the stack delivered.

const capNetRaw = 13

// Addresses from the benchmarking range (RFC 2544) and the documentation prefix
// (RFC 3849), so nothing here can collide with a network the host is really on.
// The IPv6 shunned source and sentinel sit in /64s of their own, because an
// IPv6 shun covers the whole /64.
var (
	wireLocal    = net.IPv4(198, 18, 0, 2)
	wireShunned  = net.IPv4(198, 18, 0, 10)
	wireSentinel = net.IPv4(198, 18, 0, 11)

	wireLocal6    = net.ParseIP("2001:db8:18::2")
	wireShunned6  = net.ParseIP("2001:db8:19::10")
	wireSentinel6 = net.ParseIP("2001:db8:20::11")
)

// requireRawSockets skips unless frames can be injected with AF_PACKET. That is
// the harness's need, not the gateway's, so the capability-limited CI run --
// which proves CAP_BPF and CAP_NET_ADMIN are enough -- skips these.
func requireRawSockets(t *testing.T) {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("cannot read capabilities: %v", err)
	}
	if eff, ok := effectiveCapabilities(string(status)); !ok || eff&(1<<capNetRaw) == 0 {
		t.Skip("needs CAP_NET_RAW to inject frames with an AF_PACKET socket")
	}
}

// newWirePair creates a veth pair with the receiving end addressed and both
// ends up, and removes it when the test ends. Frames written to sender arrive
// on receiver, where the programs attach.
//
// Both MACs are set at creation. A veth otherwise starts with a random one that
// systemd-udevd replaces a few milliseconds later (MACAddressPolicy=persistent),
// so a frame addressed to the MAC read at creation arrives for another host and
// the stack drops it without counting it anywhere.
func newWirePair(t *testing.T) (sender, receiver *net.Interface) {
	t.Helper()
	requireBPFCapabilities(t)
	requireRawSockets(t)

	veth := &netlink.Veth{
		LinkAttrs:        netlink.LinkAttrs{Name: "gtn-w0", HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0x18, 0x01}},
		PeerName:         "gtn-w1",
		PeerHardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0x18, 0x02},
	}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("cannot create a veth pair: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	peer, err := netlink.LinkByName("gtn-w1")
	if err != nil {
		t.Fatalf("resolve gtn-w1: %v", err)
	}
	for _, cidr := range []string{"198.18.0.2/24", "2001:db8:18::2/64"} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse address: %v", err)
		}
		// No duplicate address detection: a tentative IPv6 address accepts
		// nothing for the second or so DAD takes.
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(peer, addr); err != nil {
			t.Fatalf("address gtn-w1 with %s: %v", cidr, err)
		}
	}
	for _, l := range []netlink.Link{veth, peer} {
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("bring up %s: %v", l.Attrs().Name, err)
		}
	}
	return resolveIface(t, "gtn-w0"), resolveIface(t, "gtn-w1")
}

func resolveIface(t *testing.T, name string) *net.Interface {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return iface
}

// newInjector returns a function that writes a frame onto iface. Protocol 0
// makes the socket send-only, so it buffers nothing it would never read.
func newInjector(t *testing.T, iface *net.Interface) func(frame []byte) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatalf("AF_PACKET socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	// The protocol here only labels the socket's own copy; the frame's
	// EtherType is what the receiving side reads, IPv4 or IPv6.
	sa := &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: htons(unix.ETH_P_IP)}
	return func(frame []byte) {
		t.Helper()
		if err := unix.Sendto(fd, frame, 0, sa); err != nil {
			t.Fatalf("inject frame: %v", err)
		}
	}
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// udpFrame is an Ethernet/IPv4/UDP frame carrying payload. The IPv4 header
// checksum is valid, because the stack drops a frame without one; the UDP
// checksum is zero, which IPv4 reads as "none".
func udpFrame(to, from *net.Interface, src net.IP, port int, payload string) []byte {
	frame := make([]byte, 14+20+8+len(payload))
	copy(frame[0:6], to.HardwareAddr)
	copy(frame[6:12], from.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:], 0x0800) // ETH_P_IP
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+8+len(payload)))
	ip[8] = 64 // TTL
	ip[9] = 17 // IPPROTO_UDP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], wireLocal.To4())
	binary.BigEndian.PutUint16(ip[10:], ipv4Checksum(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], uint16(port))
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	copy(frame[42:], payload)
	return frame
}

func ipv4Checksum(header []byte) uint16 {
	return ^onesSum(0, header)
}

// onesSum folds b into a running one's-complement sum.
func onesSum(sum uint32, b []byte) uint16 {
	for i := 0; i < len(b); i += 2 {
		word := uint32(b[i]) << 8
		if i+1 < len(b) {
			word |= uint32(b[i+1])
		}
		sum += word
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// udpFrame6 is udpFrame for IPv6. The UDP checksum is mandatory there -- the
// stack drops a datagram without one -- so it is computed over the pseudo-header.
func udpFrame6(to, from *net.Interface, src net.IP, port int, payload string) []byte {
	udpLen := 8 + len(payload)
	frame := make([]byte, 14+40+udpLen)
	copy(frame[0:6], to.HardwareAddr)
	copy(frame[6:12], from.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:], 0x86DD) // ETH_P_IPV6
	ip6 := frame[14:54]
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:], uint16(udpLen))
	ip6[6] = 17 // IPPROTO_UDP
	ip6[7] = 64 // hop limit
	copy(ip6[8:24], src.To16())
	copy(ip6[24:40], wireLocal6.To16())
	udp := frame[54:]
	binary.BigEndian.PutUint16(udp[0:], 40000)
	binary.BigEndian.PutUint16(udp[2:], uint16(port))
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen))
	copy(udp[8:], payload)

	pseudo := make([]byte, 40)
	copy(pseudo[0:32], ip6[8:40])
	binary.BigEndian.PutUint32(pseudo[32:], uint32(udpLen))
	pseudo[39] = 17
	sum := ^onesSum(uint32(onesSum(0, pseudo)), udp)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
	return frame
}

// wireFamily is one address family's half of the wire test.
type wireFamily struct {
	name                     string
	network                  string // for net.ListenUDP
	local, shunned, sentinel net.IP
	frame                    func(to, from *net.Interface, src net.IP, port int, payload string) []byte
}

var wireFamilies = []wireFamily{
	{"IPv4", "udp4", wireLocal, wireShunned, wireSentinel, udpFrame},
	{"IPv6", "udp6", wireLocal6, wireShunned6, wireSentinel6, udpFrame6},
}

// readUntil returns every payload the socket delivers up to and including
// want, or fails when want does not arrive within the deadline.
func readUntil(t *testing.T, conn *net.UDPConn, want string) []string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var got []string
	buf := make([]byte, 256)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("waiting for %q (delivered so far %q): %v", want, got, err)
		}
		got = append(got, string(buf[:n]))
		if got[len(got)-1] == want {
			return got
		}
	}
}

// waitForDrops waits for the kernel to count n drops for reason. A drop is
// established by the counter moving -- something observed -- rather than by
// nothing having arrived yet.
func waitForDrops(t *testing.T, m *EbpfManager, reason string, n uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for dropped(t, m, reason) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s drop counter stayed at %d, want %d: the hook did not drop the frame",
				reason, dropped(t, m, reason), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestWireShunDropsRealPacketsOnEachHook: a shunned source's packets are
// dropped on the wire, by whichever hook Start attached, and flow again once
// the shun is lifted.
func TestWireShunDropsRealPacketsOnEachHook(t *testing.T) {
	hooks := []struct {
		name  string
		cfg   *gateonv1.EbpfConfig
		modes []string
	}{
		{"XDP", &gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true}, []string{attachModeNative}},
		{"TC", &gateonv1.EbpfConfig{Enabled: true, TcFiltering: true}, []string{attachModeTCX, attachModeClsact}},
	}
	for _, hook := range hooks {
		for _, fam := range wireFamilies {
			t.Run(hook.name+"/"+fam.name, func(t *testing.T) {
				sender, receiver := newWirePair(t)
				cfg := proto.Clone(hook.cfg).(*gateonv1.EbpfConfig)
				cfg.Interface = receiver.Name
				m := startOn(t, cfg, hook.modes)
				wireShunCycle(t, m, fam, sender, receiver)
			})
		}
	}
}

// wireShunCycle sends a source's packet, shuns it, shows its next packet is
// dropped by the hook and never delivered, then lifts the shun.
func wireShunCycle(t *testing.T, m *EbpfManager, fam wireFamily, sender, receiver *net.Interface) {
	t.Helper()
	conn, err := net.ListenUDP(fam.network, &net.UDPAddr{IP: fam.local})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	send := newInjector(t, sender)

	send(fam.frame(receiver, sender, fam.shunned, port, "before"))
	readUntil(t, conn, "before") // the control: this path delivers at all

	if err := m.ShunIP(fam.shunned.String()); err != nil {
		t.Fatalf("ShunIP: %v", err)
	}
	send(fam.frame(receiver, sender, fam.shunned, port, "shunned"))
	waitForDrops(t, m, "shunned_ip", 1)
	send(fam.frame(receiver, sender, fam.sentinel, port, "sentinel"))
	if got := readUntil(t, conn, "sentinel"); slices.Contains(got, "shunned") {
		t.Errorf("a shunned source's packet reached the socket (delivered %q)", got)
	}

	if err := m.UnshunIP(fam.shunned.String()); err != nil {
		t.Fatalf("UnshunIP: %v", err)
	}
	send(fam.frame(receiver, sender, fam.shunned, port, "after"))
	readUntil(t, conn, "after")
}

// startOn starts a manager the way the supervisor does and fails unless it
// attached in one of modes.
func startOn(t *testing.T, cfg *gateonv1.EbpfConfig, modes []string) *EbpfManager {
	t.Helper()
	m := NewEbpfManager(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		m.close()
	})
	m.Start(ctx)
	stats, err := m.GetMapStats()
	if err != nil {
		t.Fatalf("GetMapStats: %v", err)
	}
	if !stats.Attached || !slices.Contains(modes, stats.AttachMode) {
		t.Fatalf("attached=%v in mode %q (load error %q), want one of %v",
			stats.Attached, stats.AttachMode, stats.LoadError, modes)
	}
	return m
}
