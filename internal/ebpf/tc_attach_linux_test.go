// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux && !noebpf

package ebpf

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

// These exercise the attach paths against a real kernel and a real interface,
// which unit tests cannot reach: everything below the Go API — the verifier,
// the clsact qdisc, the filter install — either works on a live kernel or does
// not, and compiling proves none of it.
//
// A dummy interface is created per test rather than borrowing a real NIC, so
// nothing here can disturb host networking. Root is required for both
// CAP_NET_ADMIN and BPF program load.

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root for CAP_NET_ADMIN and BPF program load")
	}
}

// newDummyIface creates an isolated dummy interface and removes it afterwards.
func newDummyIface(t *testing.T, name string) *net.Interface {
	t.Helper()
	requireRoot(t)

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Skipf("cannot create dummy interface %q (no CAP_NET_ADMIN?): %v", name, err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })

	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("bring up %s: %v", name, err)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return iface
}

// loadTCProgram loads the compiled object and returns the TC ingress program.
func loadTCProgram(t *testing.T) *ebpf.Program {
	t.Helper()
	// Not fatal, and not a skip: the loader does not treat it as fatal either.
	// Running this test in a container that lacks CAP_SYS_RESOURCE is precisely
	// what guards against someone reinstating the hard failure.
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
	t.Cleanup(coll.Close)

	prog := coll.Programs[tcProgName]
	if prog == nil {
		t.Fatalf("program %q missing from collection", tcProgName)
	}
	return prog
}

func ingressFilterCount(t *testing.T, ifaceIndex int) int {
	t.Helper()
	nl, err := netlink.LinkByIndex(ifaceIndex)
	if err != nil {
		t.Fatalf("resolve link: %v", err)
	}
	filters, err := netlink.FilterList(nl, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return 0 // no clsact qdisc means no filters, which is the same answer
	}
	return len(filters)
}

func hasClsact(t *testing.T, ifaceIndex int) bool {
	t.Helper()
	nl, err := netlink.LinkByIndex(ifaceIndex)
	if err != nil {
		t.Fatalf("resolve link: %v", err)
	}
	qdiscs, err := netlink.QdiscList(nl)
	if err != nil {
		t.Fatalf("list qdiscs: %v", err)
	}
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			return true
		}
	}
	return false
}

// TestAttachTCAttachesAndDetaches proves the whole path works on a live kernel:
// the program passes the verifier, attaches, and reports which hook it got.
func TestAttachTCAttachesAndDetaches(t *testing.T) {
	iface := newDummyIface(t, "gwtc0")
	prog := loadTCProgram(t)

	closer, mode, err := attachTC(prog, iface)
	if err != nil {
		t.Fatalf("attachTC: %v", err)
	}
	if mode != attachModeTCX && mode != attachModeClsact {
		t.Fatalf("attachTC reported mode %q, want %q or %q", mode, attachModeTCX, attachModeClsact)
	}
	t.Logf("attached via %s", mode)

	if err := closer.Close(); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if n := ingressFilterCount(t, iface.Index); n != 0 {
		t.Errorf("%d ingress filters left behind after detach, want 0", n)
	}
}

// TestAttachClsactCreatesAndRemovesItsOwnQdisc exercises the fallback directly.
// The kernel under test is usually new enough for TCX, so without this the
// clsact path — the one that matters on the 6.1 kernels this targets — would
// never actually run.
func TestAttachClsactCreatesAndRemovesItsOwnQdisc(t *testing.T) {
	iface := newDummyIface(t, "gwtc1")
	prog := loadTCProgram(t)

	if hasClsact(t, iface.Index) {
		t.Fatal("fresh dummy interface already has a clsact qdisc")
	}

	closer, err := attachClsact(prog, iface)
	if err != nil {
		t.Fatalf("attachClsact: %v", err)
	}
	if !hasClsact(t, iface.Index) {
		t.Error("clsact qdisc was not created")
	}
	if n := ingressFilterCount(t, iface.Index); n != 1 {
		t.Errorf("got %d ingress filters, want 1", n)
	}

	if err := closer.Close(); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if hasClsact(t, iface.Index) {
		t.Error("clsact qdisc we created was left behind")
	}
}

// TestAttachClsactLeavesABorrowedQdiscAlone is the guard on the destructive
// case. Deleting a clsact qdisc takes every filter on it, including egress
// filters belonging to a CNI or another agent, so teardown must remove only a
// qdisc it created itself. Getting this wrong is someone else's outage.
func TestAttachClsactLeavesABorrowedQdiscAlone(t *testing.T) {
	iface := newDummyIface(t, "gwtc2")
	prog := loadTCProgram(t)

	// Stand in for the CNI: the qdisc exists before we arrive.
	preexisting := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(preexisting); err != nil {
		t.Fatalf("pre-create clsact: %v", err)
	}

	closer, err := attachClsact(prog, iface)
	if err != nil {
		t.Fatalf("attachClsact: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("detach: %v", err)
	}

	if !hasClsact(t, iface.Index) {
		t.Fatal("teardown removed a clsact qdisc it did not create")
	}
	if n := ingressFilterCount(t, iface.Index); n != 0 {
		t.Errorf("%d filters left on the borrowed qdisc, want 0", n)
	}
}
