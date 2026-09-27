// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package phantom

import (
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// shared holds the one io_uring core the tests in this package use unless they
// need to close a core themselves.
//
// It is shared because a ring is never given back: go-uring's Ring.Close
// unmaps the submission and completion rings but not the SQE array, so the
// mapping keeps the whole io_uring instance -- and its charge against locked
// memory -- alive until the process exits. Four create-and-close cycles
// exhaust the default 8 MiB RLIMIT_MEMLOCK, after which newPhantomCore falls
// back to standard I/O without a word, and every io_uring test after that
// would pass against the fallback instead of the ring.
var shared struct {
	once sync.Once
	core *linuxCore
}

// uringCore returns a core with a live ring, built the way cmd/gateon builds
// it: GATEON_PHANTOM=1 and an eBPF manager that is never nil.
func uringCore(t *testing.T) *linuxCore {
	t.Helper()
	shared.once.Do(func() { shared.core = newUringCore(t) })
	if shared.core == nil {
		t.Skip("io_uring is unavailable here (seccomp, SELinux, io_uring_disabled " +
			"or locked memory): these tests prove nothing about the ring on this host")
	}
	return shared.core
}

// newUringCore builds a core of the caller's own, for a test that closes it.
// It returns nil when the kernel refuses a ring.
func newUringCore(t *testing.T) *linuxCore {
	t.Helper()
	t.Setenv("GATEON_PHANTOM", "1")
	c, ok := newPhantomCore(holderLike{}).(*linuxCore)
	if !ok || c.ring == nil {
		return nil
	}
	return c
}

// listenOptimized returns a loopback listener wrapped by core, closed when the
// test ends.
func listenOptimized(t *testing.T, core *linuxCore) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	opt := core.OptimizeListener(ln)
	if _, ok := opt.(*iouringListener); !ok {
		_ = ln.Close()
		t.Fatalf("OptimizeListener returned %T with a live ring; want *iouringListener", opt)
	}
	t.Cleanup(func() { _ = opt.Close() })
	return opt
}

// waitForParkedAccept returns once a goroutine is parked inside the io_uring
// Accept: its operation has been queued and it is waiting for the completion.
// A stack dump is the only place that state is visible from outside, and it is
// a barrier rather than a guess at how long queueing takes.
func waitForParkedAccept(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "[select") && strings.Contains(g, "(*iouringListener).Accept") {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("no goroutine ever parked in the io_uring Accept")
}

// sockaddrSized has the size class of unix.RawSockaddrAny, the buffer an
// io_uring accept hands the kernel for the peer's address.
type sockaddrSized [112]byte

const sprayByte = 0xAA

// sprayFreedSlots allocates enough sockaddr-sized objects, each filled with a
// known byte, to take over any slot of that size the collector just freed.
func sprayFreedSlots() []*sockaddrSized {
	spray := make([]*sockaddrSized, 20000)
	for i := range spray {
		o := new(sockaddrSized)
		for j := range o {
			o[j] = sprayByte
		}
		spray[i] = o
	}
	return spray
}

// overwritten returns the first sprayed object whose leading bytes -- where
// the kernel writes a sockaddr -- are no longer the sprayed byte.
func overwritten(spray []*sockaddrSized) []byte {
	for _, o := range spray {
		for j := 0; j < 16; j++ {
			if o[j] != sprayByte {
				return o[:16]
			}
		}
	}
	return nil
}

// TestUringAcceptKeepsTheAddressBufferUntilTheKernelWritesIt is heap
// corruption on every optimized listener.
//
// The accept operation carries the buffer the kernel writes the peer's address
// into, and the SQE refers to it by a bare integer, which the collector does
// not see. Accept dropped its last reference to the operation as soon as it was
// queued, so a collection while the accept was pending -- which is most of the
// time for a listener -- freed that buffer, the allocator handed it to
// something else, and the next connection wrote its sockaddr_in over it: the
// client's own address and port, into an arbitrary live object. It overwrote a
// pointer often enough to take the process down with an unexpected fault.
func TestUringAcceptKeepsTheAddressBufferUntilTheKernelWritesIt(t *testing.T) {
	opt := listenOptimized(t, uringCore(t))
	for round := 0; round < 20; round++ {
		accepted := make(chan net.Conn, 1)
		go func() {
			c, _ := opt.Accept()
			accepted <- c
		}()
		waitForParkedAccept(t)
		runtime.GC()
		spray := sprayFreedSlots()
		client, err := net.Dial("tcp", opt.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		server := <-accepted
		hit := overwritten(spray)
		_ = client.Close()
		if server != nil {
			_ = server.Close()
		}
		if hit != nil {
			t.Fatalf("round %d: the kernel wrote the peer's address (% x) into memory "+
				"the collector had freed from a pending accept and reallocated", round, hit)
		}
		runtime.KeepAlive(spray)
	}
}

// TestStatusNamesIOURingWhileItsRingIsUp is the other half of
// TestStatusClaimsNoAccelerationThatIsNotRunning: with a ring up, the engine
// is io_uring and nothing more. It read "io_uring + AF_XDP" here, because the
// eBPF manager that is always present was taken as evidence of AF_XDP.
func TestStatusNamesIOURingWhileItsRingIsUp(t *testing.T) {
	core := uringCore(t)
	enabled, engine, _ := core.GetStatus()
	if !enabled || engine != "io_uring" {
		t.Errorf("GetStatus with a live ring = (%v, %q), want (true, \"io_uring\")",
			enabled, engine)
	}
}
