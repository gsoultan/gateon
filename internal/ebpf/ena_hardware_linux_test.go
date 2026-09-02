// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Everything gateon says about native XDP on EC2 -- that the ENA driver refuses
// it above a page-sized MTU, and unless the driver is using at most half its
// queues -- was reasoned from driver behaviour and never met the hardware. The
// preflight in attach.go quotes specific numbers to operators on that basis.
//
// This checks the prediction against a real ENA interface. It is not a smoke
// test: it works out what the diagnosis claims *before* attempting the attach,
// then attempts it, and fails when the two disagree in either direction. A
// diagnosis that says "blocked" where XDP in fact attaches is as wrong as one
// that says nothing while the attach fails.
//
// Opt-in, because it asserts things about the host it runs on. Set
// GATEON_VERIFY_ENA=1, which the ena-verify workflow does on a self-hosted
// runner inside AWS.

func requireENAHost(t *testing.T) *net.Interface {
	t.Helper()
	if os.Getenv("GATEON_VERIFY_ENA") == "" {
		t.Skip("set GATEON_VERIFY_ENA=1 to run against real ENA hardware")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root for CAP_NET_ADMIN and BPF program load")
	}

	name := os.Getenv("GATEON_VERIFY_IFACE")
	if name == "" {
		// Modern EC2 AMIs name the primary interface ens5 or enX0; eth0 is the
		// old naming and is also what a container netns uses.
		for _, candidate := range []string{"ens5", "enX0", "eth0"} {
			if _, err := net.InterfaceByName(candidate); err == nil {
				name = candidate
				break
			}
		}
	}
	if name == "" {
		t.Skip("no candidate interface found; set GATEON_VERIFY_IFACE")
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return iface
}

// TestENADiagnosisMatchesRealHardware is the check that has been missing.
func TestENADiagnosisMatchesRealHardware(t *testing.T) {
	iface := requireENAHost(t)
	facts := probeNIC(iface)

	t.Logf("interface   %s", facts.Name)
	t.Logf("driver      %q", facts.Driver)
	t.Logf("MTU         %d", facts.MTU)
	t.Logf("RX queues   %d on %d CPUs", facts.RXQueues, facts.NumCPU)
	t.Logf("page size   %d  -> native-XDP MTU ceiling ~%d", facts.PageSize, nativeXDPMaxMTU(facts.PageSize))

	if facts.Driver != "ena" {
		t.Skipf("driver is %q, not ena; this check is about the ENA claims specifically", facts.Driver)
	}

	// What the preflight would tell an operator, decided before we try.
	causes, remedies := nativeXDPBlockers(facts)
	predictBlocked := len(causes) > 0
	for _, c := range causes {
		t.Logf("predicted blocker: %s", c)
	}
	for _, r := range remedies {
		t.Logf("suggested remedy:  %s", r)
	}

	// Now find out. A native attach either works on this host or it does not.
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("memlock rlimit not raised (%v); continuing, as the loader does", err)
	}
	spec, err := loadGateon_ebpf()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("create collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[xdpProgName]
	if prog == nil {
		t.Fatalf("program %q missing", xdpProgName)
	}

	l, nativeErr := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index})
	if nativeErr == nil {
		defer func() { _ = l.Close() }()
	}
	actuallyBlocked := nativeErr != nil
	t.Logf("native XDP attach: blocked=%v err=%v", actuallyBlocked, nativeErr)

	switch {
	case predictBlocked && !actuallyBlocked:
		t.Fatalf("the preflight would have told an operator native XDP is unavailable (%s), "+
			"but it attached. The advice is wrong for this host.", strings.Join(causes, "; "))

	case !predictBlocked && actuallyBlocked:
		// The dangerous direction: the attach fails and gateon has no specific
		// reason to offer, so the operator gets the driver's bare errno.
		d := diagnoseNativeXDP(facts, false, nativeErr)
		t.Fatalf("native XDP was refused but the preflight found no blocker to name. "+
			"Operators would see only: %s", d.Summary)

	case predictBlocked && actuallyBlocked:
		d := diagnoseNativeXDP(facts, false, nativeErr)
		t.Logf("diagnosis: %s", d.Summary)
		// The message has to carry the real numbers, not a generic sentence.
		if facts.MTU > nativeXDPMaxMTU(facts.PageSize) &&
			!strings.Contains(d.Summary, "MTU") {
			t.Error("MTU is over the ceiling but the diagnosis does not mention MTU")
		}
		if len(remedies) == 0 {
			t.Error("a blocked attach produced no remediation command")
		}

	default:
		t.Log("native XDP attached and the preflight predicted no blocker: consistent")
	}
}

// TestENATCFallbackAttaches confirms the path gateon actually recommends on this
// hardware. If native XDP is unavailable here, tc_filtering is the advice, and
// advice that has never been run on the target is not advice.
func TestENATCFallbackAttaches(t *testing.T) {
	iface := requireENAHost(t)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Logf("memlock rlimit not raised (%v); continuing", err)
	}
	spec, err := loadGateon_ebpf()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("create collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[tcProgName]
	if prog == nil {
		t.Fatalf("program %q missing", tcProgName)
	}

	closer, mode, err := attachTC(prog, iface)
	if err != nil {
		t.Fatalf("TC attach failed on the interface gateon recommends it for: %v", err)
	}
	t.Logf("TC attached via %s on %s", mode, iface.Name)

	if err := closer.Close(); err != nil {
		t.Errorf("detach: %v", err)
	}
}
