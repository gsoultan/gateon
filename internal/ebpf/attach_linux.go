// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gsoultan/gateon/internal/logger"
)

// Attach modes reported through MapStats.AttachMode.
const (
	attachModeNative  = "native"
	attachModeGeneric = "generic"
	attachModeTCX     = "tcx"
	attachModeClsact  = "clsact"
)

// sysfsNet is the root of the kernel's per-interface attribute tree. Reading it
// costs two file operations at attach time and needs no privileges, unlike the
// ethtool ioctl that would otherwise be required to learn the same things.
const sysfsNet = "/sys/class/net"

// safeIfaceName rejects anything that could escape the sysfs tree. The name has
// already been resolved by net.InterfaceByName so it is kernel-validated in
// practice; this keeps the guarantee local to the code doing the path join
// rather than depending on a caller three frames up.
func safeIfaceName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/\\") && name != "." && name != ".."
}

// sysfsDriver returns the kernel driver bound to the interface ("ena" on EC2,
// "virtio_net" under QEMU/GCE, "" for veth and other virtual devices that have
// no backing PCI device). Used only to make the diagnosis more specific.
func sysfsDriver(name string) string {
	if !safeIfaceName(name) {
		return ""
	}
	dst, err := os.Readlink(filepath.Join(sysfsNet, name, "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(dst)
}

// sysfsRXQueues counts the interface's RX queues. This is the current count;
// the driver's maximum is only readable over ethtool netlink, which is why the
// queue diagnosis compares against the CPU count instead of the true maximum.
func sysfsRXQueues(name string) int {
	if !safeIfaceName(name) {
		return 0
	}
	entries, err := os.ReadDir(filepath.Join(sysfsNet, name, "queues"))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			n++
		}
	}
	return n
}

// probeNIC gathers what the diagnosis needs. Every lookup degrades to a zero
// value, because a missing fact must narrow the explanation, never invent one.
func probeNIC(iface *net.Interface) nicFacts {
	return nicFacts{
		Name:     iface.Name,
		Driver:   sysfsDriver(iface.Name),
		MTU:      iface.MTU,
		RXQueues: sysfsRXQueues(iface.Name),
		NumCPU:   runtime.NumCPU(),
		PageSize: os.Getpagesize(),
	}
}

// attachXDP attaches the XDP program in native driver mode — the only mode that
// pays for itself, because it runs before the skb is allocated and so a dropped
// packet costs nothing downstream.
//
// When the driver refuses, it does NOT silently degrade. Generic/SKB mode runs
// in netif_receive_generic_xdp() after the skb already exists, so it drops no
// earlier than an nftables rule while still charging every passed packet the
// full program cost, plus a pskb_expand_head() when the skb lacks the 256-byte
// XDP headroom and an skb_linearize() when it is non-linear. On a jumbo-MTU ENA
// interface that is two extra allocations and two copies per packet in exchange
// for nothing, which is why it now takes an explicit opt-in.
func attachXDP(prog *ebpf.Program, iface *net.Interface, allowGeneric bool) (link.Link, string, error) {
	// Default flags (0) ask the kernel for the best available native attach; it
	// does not fall back to generic on its own.
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index})
	if err == nil {
		return l, attachModeNative, nil
	}
	nativeErr := err

	diag := diagnoseNativeXDP(probeNIC(iface), allowGeneric, nativeErr)
	for _, remedy := range diag.Remedies {
		logger.L.LogWarn("native XDP remedy", "interface", iface.Name, "run", remedy)
	}

	if !allowGeneric {
		return nil, "", errors.New(diag.Summary)
	}

	logger.L.LogWarn(diag.Summary, "interface", iface.Name)
	l, err = link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err == nil {
		return l, attachModeGeneric, nil
	}
	return nil, "", fmt.Errorf("%s; generic mode also failed: %w", diag.Summary, err)
}
