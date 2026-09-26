// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/ebpf/link"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/vishvananda/netlink"
)

// With no mode flag the kernel attaches XDP in driver mode when the driver
// implements it, and in SKB (generic) mode when it does not (dev_xdp_mode in
// net/core/dev.c). attachXDP passed no flag and reported every successful
// attach as native, so a NIC without native XDP -- e1000, r8169, a bridge, a
// dummy -- ran the generic mode ADR 0007 refuses by default while the dashboard
// said "native". ENA was never affected: it implements native XDP and refuses
// the attach outright.

// TestNativeXDPAttachIsNeverGenericInDisguise: on a device without native XDP
// the native attempt must be refused, so Start falls back to TC -- and generic
// mode is still there for whoever opts into it.
func TestNativeXDPAttachIsNeverGenericInDisguise(t *testing.T) {
	iface := newDummyIface(t, "gtn-nodrv")
	prog := loadProgram(t, xdpProgName)

	// The control: this device really has no native XDP. Asked for driver mode
	// by name, the kernel refuses.
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index, Flags: link.XDPDriverMode})
	if err == nil {
		_ = l.Close()
		t.Skip("this kernel's dummy driver implements native XDP; the test needs a device without it")
	}

	l, mode, err := attachXDP(prog, iface, false)
	if err == nil {
		_ = l.Close()
		t.Fatalf("attachXDP reported a %q attach on a device the kernel will not attach to in driver "+
			"mode: with no mode flag it attached in generic (SKB) mode, which was not opted into", mode)
	}

	l, mode, err = attachXDP(prog, iface, true)
	if err != nil {
		t.Fatalf("generic mode was opted into and the attach still failed: %v", err)
	}
	defer func() { _ = l.Close() }()
	if mode != attachModeGeneric {
		t.Errorf("opted-in fallback reported mode %q, want %q", mode, attachModeGeneric)
	}
}

// TestNativeXDPAttachStillAttachesNatively is the other half: asking for driver
// mode by name must not cost a driver that has it. veth implements native XDP.
func TestNativeXDPAttachStillAttachesNatively(t *testing.T) {
	requireRoot(t)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "gtn-veth0"}, PeerName: "gtn-veth1"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("cannot create a veth pair: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	if err := netlink.LinkSetUp(veth); err != nil {
		t.Fatalf("bring up gtn-veth0: %v", err)
	}
	iface, err := net.InterfaceByName("gtn-veth0")
	if err != nil {
		t.Fatalf("resolve gtn-veth0: %v", err)
	}

	l, mode, err := attachXDP(loadProgram(t, xdpProgName), iface, false)
	if err != nil {
		t.Fatalf("native attach refused on veth, which implements native XDP: %v", err)
	}
	defer func() { _ = l.Close() }()
	if mode != attachModeNative {
		t.Errorf("attach mode %q on veth, want %q", mode, attachModeNative)
	}
}

// TestStartFallsBackToTCWhenNativeXDPIsRefused: a dummy interface has no native
// XDP, as an ENA interface at the EC2 defaults has none. With an XDP feature on
// and tc_filtering off, Start used to leave nothing attached.
func TestStartFallsBackToTCWhenNativeXDPIsRefused(t *testing.T) {
	iface := newDummyIface(t, "gtn-fallback")
	m := NewEbpfManager(&gateonv1.EbpfConfig{Enabled: true, XdpIpShunning: true, Interface: iface.Name})
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
	if !stats.Attached {
		t.Fatalf("nothing attached after native XDP was refused (load error %q): "+
			"Start did not fall back to the TC hook", stats.LoadError)
	}
	if stats.AttachMode != attachModeTCX && stats.AttachMode != attachModeClsact {
		t.Errorf("attached in mode %q, want the TC hook (tcx or clsact): a dummy interface has "+
			"no native XDP, and generic mode was not opted into", stats.AttachMode)
	}
	if stats.Interface != iface.Name {
		t.Errorf("attached to %q, want the configured %q", stats.Interface, iface.Name)
	}
}
