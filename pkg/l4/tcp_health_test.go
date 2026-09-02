// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"net"
	"testing"
)

// These drive the real dial path against real listeners rather than stubbing it.
// The thing under test is what a TCP connect result means, so faking the connect
// would test the arithmetic and not the behaviour.

// listenerAddr starts a listener and returns its address plus a close func, so a
// test can take a backend down mid-flight.
func listenerAddr(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closed := false
	stop := func() {
		if !closed {
			closed = true
			_ = ln.Close()
		}
	}
	t.Cleanup(stop)
	return ln.Addr().String(), stop
}

// deadAddr returns an address with nothing listening: a listener opened to
// reserve the port, then closed.
func deadAddr(t *testing.T) string {
	t.Helper()
	addr, stop := listenerAddr(t)
	stop()
	return addr
}

// TestSingleFailureDoesNotEvictABackend is the regression guard. A single dial
// result used to flip state outright, so one transient timeout removed a healthy
// backend from rotation -- and with a small pool that is a capacity cliff caused
// by a blip.
func TestSingleFailureDoesNotEvictABackend(t *testing.T) {
	live, stopLive := listenerAddr(t)
	p := NewTCPBackendPool([]string{live}, "round_robin", 10000, 100, false)

	stopLive() // the backend goes away
	p.healthCheck()

	if !p.alive[0].Load() {
		t.Fatal("one failed check evicted the backend; a transient blip is not an outage")
	}
	if p.Pick() != live {
		t.Error("Pick stopped returning a backend after a single failed check")
	}
}

func TestConsecutiveFailuresEvictABackend(t *testing.T) {
	live, stopLive := listenerAddr(t)
	p := NewTCPBackendPool([]string{live}, "round_robin", 10000, 100, false)
	stopLive()

	for i := 0; i < tcpFailThreshold; i++ {
		p.healthCheck()
	}

	if p.alive[0].Load() {
		t.Fatalf("backend still marked alive after %d consecutive failures", tcpFailThreshold)
	}
	if got := p.Pick(); got != "" {
		t.Errorf("Pick returned %q with every backend down, want empty", got)
	}
}

// A success between failures resets the count, so intermittent failures spread
// across intervals must not accumulate into an eviction.
func TestInterruptedFailuresDoNotAccumulate(t *testing.T) {
	live, stopLive := listenerAddr(t)
	p := NewTCPBackendPool([]string{live}, "round_robin", 10000, 100, false)

	// Two failures, short of the threshold.
	stopLive()
	p.healthCheck()
	p.healthCheck()

	// Then a success, which must clear the tally.
	revived, _ := listenerAddr(t)
	p.addrs[0] = revived
	p.healthCheck()

	// Two more failures should still be short of the threshold.
	p.addrs[0] = deadAddr(t)
	p.healthCheck()
	p.healthCheck()

	if !p.alive[0].Load() {
		t.Fatal("failures separated by a success accumulated into an eviction")
	}
}

// TestRecoveryRequiresMoreThanOneSuccess is the other half. A TCP connect says
// nothing about whether the application behind it is ready, so a single
// successful dial is not enough to send traffic back.
func TestRecoveryRequiresMoreThanOneSuccess(t *testing.T) {
	p := NewTCPBackendPool([]string{deadAddr(t)}, "round_robin", 10000, 100, false)

	for i := 0; i < tcpFailThreshold; i++ {
		p.healthCheck()
	}
	if p.alive[0].Load() {
		t.Fatal("setup: backend should be down")
	}

	revived, _ := listenerAddr(t)
	p.addrs[0] = revived

	p.healthCheck()
	if p.alive[0].Load() {
		t.Fatalf("one successful dial restored the backend; %d are required", tcpRiseThreshold)
	}

	for i := 1; i < tcpRiseThreshold; i++ {
		p.healthCheck()
	}
	if !p.alive[0].Load() {
		t.Fatalf("backend not restored after %d consecutive successes", tcpRiseThreshold)
	}
}

// Pick must route around a down backend rather than blackholing traffic to it.
func TestPickSkipsDownBackends(t *testing.T) {
	good, _ := listenerAddr(t)
	bad := deadAddr(t)

	p := NewTCPBackendPool([]string{bad, good}, "round_robin", 10000, 100, false)
	for i := 0; i < tcpFailThreshold; i++ {
		p.healthCheck()
	}

	for i := 0; i < 8; i++ {
		if got := p.Pick(); got != good {
			t.Fatalf("Pick returned %q, want the only healthy backend %q", got, good)
		}
	}
}

// Release has to balance Pick, or active counts drift upward until least_conn
// believes every backend is saturated.
func TestReleaseBalancesPickForLeastConn(t *testing.T) {
	a, _ := listenerAddr(t)
	b, _ := listenerAddr(t)
	p := NewTCPBackendPool([]string{a, b}, "least_conn", 10000, 100, false)

	for i := 0; i < 10; i++ {
		p.Release(p.Pick())
	}

	for i := range p.addrs {
		if got := p.active[i].Load(); got != 0 {
			t.Errorf("backend %d has %d active connections after balanced pick/release, want 0", i, got)
		}
	}
}

// Stop must be safe to call more than once; it is reached from both an explicit
// shutdown and a deferred cleanup.
func TestStopIsIdempotent(t *testing.T) {
	addr, _ := listenerAddr(t)
	p := NewTCPBackendPool([]string{addr}, "round_robin", 10000, 100, false)
	p.Stop()
	p.Stop()
}

func TestNewTCPBackendPoolRejectsAnEmptyPool(t *testing.T) {
	if p := NewTCPBackendPool(nil, "round_robin", 0, 0, false); p != nil {
		t.Error("a pool with no backends should be nil, not an empty pool that always returns none")
	}
}
