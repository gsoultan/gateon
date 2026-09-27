// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build linux

package phantom

import (
	"io"
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

// waitForParked returns once a goroutine is parked in a select inside the named
// function: its io_uring op has been queued and it is waiting for the
// completion. A stack dump is the only place that state is visible from
// outside, and it is a barrier rather than a guess at how long queueing takes.
func waitForParked(t *testing.T, fn string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "[select") && strings.Contains(g, fn) {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("no goroutine ever parked in %s", fn)
}

func waitForParkedAccept(t *testing.T) {
	t.Helper()
	waitForParked(t, "(*iouringListener).Accept")
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

// acceptOne accepts a single connection from opt and returns it.
func acceptOne(t *testing.T, opt net.Listener) (server, client net.Conn) {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := opt.Accept()
		ch <- res{c, err}
	}()
	client, err := net.Dial("tcp", opt.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	return r.c, client
}

// TestUringWriteDeliversEveryByteOrReportsAnError pins the io.Writer contract
// on the optimized connection.
//
// One io_uring write op transfers as much as the socket send buffer takes and
// reports that count. Write returned it with a nil error, so a Write of more
// than the send buffer -- a large HTTP response body, exactly what this path is
// meant to speed up -- returned n < len(b) and err == nil. io.Copy and
// net/http's response writer take that as success and move on, and the tail of
// every large write was dropped.
func TestUringWriteDeliversEveryByteOrReportsAnError(t *testing.T) {
	opt := listenOptimized(t, uringCore(t))
	server, client := acceptOne(t, opt)
	defer server.Close()
	defer client.Close()

	received := make(chan int, 1)
	go func() {
		n, _ := io.Copy(io.Discard, client) // drains fully, so a correct Write completes
		received <- int(n)
	}()

	payload := make([]byte, 32<<20) // larger than any default socket send buffer
	for i := range payload {
		payload[i] = byte(i)
	}
	n, err := server.Write(payload)
	if n < len(payload) && err == nil {
		t.Fatalf("Write returned (%d, nil) for a %d-byte buffer: a short write with no "+
			"error tells io.Copy and net/http the whole buffer was sent, so the "+
			"remaining %d bytes are silently dropped", n, len(payload), len(payload)-n)
	}
	if err != nil {
		t.Fatalf("Write to a fully-draining peer failed: %v", err)
	}
	_ = server.Close()
	if got := <-received; got != len(payload) {
		t.Fatalf("the peer received %d of %d bytes", got, len(payload))
	}
}

// TestUringZeroLengthIODoesNotCrash covers an empty buffer, which http/2 frame
// writing and bufio can both hand a conn.
//
// The read and write ops take &buf[0] unconditionally, which panics on a
// zero-length slice; worse, the op had already been queued when the panic
// unwound, leaving the reactor a nil callback to invoke on the completion,
// which took the whole process down rather than one connection.
func TestUringZeroLengthIODoesNotCrash(t *testing.T) {
	opt := listenOptimized(t, uringCore(t))
	server, client := acceptOne(t, opt)
	defer server.Close()
	defer client.Close()

	if n, err := server.Write([]byte{}); n != 0 || err != nil {
		t.Fatalf("Write(empty) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := server.Read([]byte{}); n != 0 || err != nil {
		t.Fatalf("Read(empty) = (%d, %v), want (0, nil)", n, err)
	}

	// The reactor must still be alive: a real exchange has to go through.
	go func() { _, _ = client.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatalf("a real read after the empty ops failed, so the reactor did not "+
			"survive them: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("read %q after empty ops, want \"ping\"", buf)
	}
}

// TestUringWriteAfterCloseDoesNotReachAReusedDescriptor pins that a closed
// optimized connection stops touching its descriptor.
//
// iouringConn caches the integer fd at accept time and Read/Write name it
// directly. The embedded net.Conn's Close closes that fd but nothing marked the
// wrapper closed, so a Read or Write arriving after Close still issued an
// io_uring op against the bare number -- which the kernel had already handed to
// the next accepted connection. A late write then delivered one client's bytes
// to another's socket.
func TestUringWriteAfterCloseDoesNotReachAReusedDescriptor(t *testing.T) {
	opt := listenOptimized(t, uringCore(t))
	closed, _ := acceptOne(t, opt)
	fd := closed.(*iouringConn).fd

	// A second client waits in the backlog, then closed is shut. Its fd is now
	// free and the lowest available, so the next accept reuses that number.
	victimBacking, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer victimBacking.Close()
	victimClient, err := net.Dial("tcp", victimBacking.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer victimClient.Close()

	if err := closed.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	victimServer, err := victimBacking.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer victimServer.Close()
	reused := victimServer.(*net.TCPConn)
	var reusedFd int
	rc, _ := reused.SyscallConn()
	_ = rc.Control(func(f uintptr) { reusedFd = int(f) })
	if reusedFd != fd {
		t.Skipf("the kernel did not reuse fd %d (gave %d), so this run cannot "+
			"observe the confusion", fd, reusedFd)
	}

	secret := []byte("secret for the connection that was closed\n")
	n, werr := closed.Write(secret)
	t.Logf("Write on the closed conn: n=%d err=%v", n, werr)

	_ = victimClient.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, len(secret))
	m, rerr := victimClient.Read(buf)
	if m > 0 {
		t.Fatalf("the victim connection received %q, written by a Write on a "+
			"different, already-closed connection whose fd it reused", buf[:m])
	}
	t.Logf("victim read ended with %v (no leaked bytes)", rerr)
}

// cancelWithoutClosing cancels a core's context the way Close's first step
// does, but leaves the ring mapped so the kernel keeps and later completes the
// ops that were in flight. That is the window Close opens: cancel() wakes every
// parked Accept/Read/Write before <-reactorDone and ring.Close() run.
func cancelWithoutClosing(t *testing.T, core *linuxCore) {
	t.Helper()
	if core.cancel == nil {
		t.Fatal("core has no cancel; not an io_uring core")
	}
	core.cancel()
}

// dedicatedCore builds a core the test owns, skipping when io_uring is
// unavailable. Its ring is intentionally never closed: go-uring does not
// reclaim a closed ring anyway, and these tests must leave it mapped so the
// kernel completes the abandoned op.
func dedicatedCore(t *testing.T) *linuxCore {
	t.Helper()
	c := newUringCore(t)
	if c == nil {
		t.Skip("io_uring is unavailable here; this test proves nothing about the ring")
	}
	return c
}

// TestUringAcceptBufferSurvivesAContextCancel is the ctx.Done half of the
// keep-alive: cancelling the core (Close's first step) wakes a parked Accept and
// it returns, but the accept is still pending in the kernel. defer KeepAlive(op)
// ends at that return, so the op -- which owns the buffer the kernel writes the
// peer's address into -- became collectable while the kernel still had it. A GC
// and then a connecting client wrote a sockaddr into freed, reused memory.
func TestUringAcceptBufferSurvivesAContextCancel(t *testing.T) {
	core := dedicatedCore(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	opt := core.OptimizeListener(ln)

	returned := make(chan struct{})
	go func() {
		c, _ := opt.Accept()
		if c != nil {
			_ = c.Close()
		}
		close(returned)
	}()
	waitForParkedAccept(t)
	time.Sleep(50 * time.Millisecond) // let the publisher submit the SQE to the kernel

	cancelWithoutClosing(t, core)
	select {
	case <-returned:
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not return after the core context was cancelled")
	}

	runtime.GC()
	spray := sprayFreedSlots()
	client, err := net.Dial("tcp", opt.Addr().String()) // completes the pending accept
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	time.Sleep(200 * time.Millisecond)

	if hit := overwritten(spray); hit != nil {
		t.Fatalf("after Accept returned on context cancel, the kernel wrote the peer's "+
			"address (% x) into memory freed from the abandoned accept and reused", hit)
	}
	runtime.KeepAlive(spray)
}

// TestUringReadBufferStaysReachableAfterContextCancel is the same hole on Read,
// tested at its root: the buffer the kernel will fill must not become
// collectable while the read is still pending. The read buffer belongs to the
// op; when the caller keeps no other reference to it -- a short-lived read
// buffer -- the op is all that holds it. Cancelling the core woke the parked
// Read and returned, defer KeepAlive(op) then ended, and the buffer became
// eligible for collection while the kernel still had the read queued. A
// finalizer on the buffer fires exactly when that happens.
func TestUringReadBufferStaysReachableAfterContextCancel(t *testing.T) {
	core := dedicatedCore(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	opt := core.OptimizeListener(ln)
	server, client := acceptOne(t, opt)
	defer server.Close()
	defer client.Close()

	freed := make(chan struct{})
	started := make(chan struct{})
	go func() {
		buf := new(sockaddrSized) // only the pending op will reference it after Read returns
		runtime.SetFinalizer(buf, func(*sockaddrSized) { close(freed) })
		close(started)
		_, _ = server.Read(buf[:])
		// buf leaves scope here; the goroutine exits.
	}()
	<-started
	waitForParked(t, "(*iouringConn).awaitOp")
	time.Sleep(50 * time.Millisecond) // let the read SQE reach the kernel

	cancelWithoutClosing(t, core)
	time.Sleep(100 * time.Millisecond) // let the woken Read return and its goroutine exit

	// Force collection; if the buffer is unreachable its finalizer runs.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	select {
	case <-freed:
		t.Fatal("the read buffer was collected while its io_uring read was still pending " +
			"in the kernel: on the next byte the kernel copies received data into freed memory")
	case <-time.After(2 * time.Second):
		// stayed reachable until the (never-arriving) completion, as it must
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
