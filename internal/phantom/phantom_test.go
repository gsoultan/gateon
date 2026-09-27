// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package phantom

import (
	"net"
	"strings"
	"testing"
)

func TestPhantomCore_Optimize(t *testing.T) {
	core := NewPhantomCore(nil)
	defer core.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	opt := core.OptimizeListener(l)
	if opt == nil {
		t.Error("Expected listener, got nil")
	}
}

// holderLike stands in for what cmd/gateon passes NewPhantomCore:
// ebpf.GlobalHolder, a *Holder that is never nil whether or not an eBPF program
// is loaded. So "an eBPF manager was passed" is true on every install and says
// nothing about whether anything is accelerated.
type holderLike struct{}

func (holderLike) RegisterPhantomPort(uint32) error   { return nil }
func (holderLike) UnregisterPhantomPort(uint32) error { return nil }

// TestStatusClaimsNoAccelerationThatIsNotRunning pins what the Diagnostics
// page's Phantom Core card is fed.
//
// GetStatus appended "AF_XDP" and reported enabled whenever it held an eBPF
// manager, which main always gives it. So every Linux install -- io_uring off,
// the default -- showed OPTIMIZED over the engine name "standardAF_XDP". No path
// in this package moves a byte over AF_XDP: proxyWithXDP returns an error on
// every call and ProxyL4 falls back to splice.
//
// It replaces a test that asserted only that the engine string was not empty,
// which any answer at all satisfies.
func TestStatusClaimsNoAccelerationThatIsNotRunning(t *testing.T) {
	t.Setenv("GATEON_PHANTOM", "")
	core := NewPhantomCore(holderLike{})
	defer func() { _ = core.Close() }()

	enabled, engine, _ := core.GetStatus()
	if enabled {
		t.Errorf("GetStatus reports enabled with io_uring off (engine %q): the "+
			"dashboard shows OPTIMIZED while nothing is", engine)
	}
	if strings.Contains(engine, "AF_XDP") {
		t.Errorf("GetStatus reports engine %q, but nothing in this package runs "+
			"AF_XDP: proxyWithXDP fails on every call", engine)
	}
}
