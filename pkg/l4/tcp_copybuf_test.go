// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
)

// unsplicedSession runs one session through pool.ProxyTCP whose client end is
// a net.Pipe -- a connection splice cannot move, like the TLS connection a
// TLS-terminating entrypoint hands the proxy -- and echoes one message.
func unsplicedSession(t testing.TB, pool *TCPBackendPool, msg, buf []byte) {
	t.Helper()
	client, proxySide := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.ProxyTCP(context.Background(), proxySide)
	}()
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatalf("echo: %v", err)
	}
	_ = client.Close()
	<-done
}

// echoBackend echoes every connection until stop.
func echoBackend(t testing.TB) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	served := make(chan struct{})
	var handlers sync.WaitGroup
	go func() {
		defer close(served)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			handlers.Go(func() { // ends when the proxy closes its side
				defer c.Close()
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			})
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-served
		handlers.Wait()
	}
}

// TestAnUnsplicedSessionReusesItsCopyBuffers: a session splice cannot move --
// every one through a TLS-terminating TCP entrypoint -- is copied through a
// user-space buffer each way. io.Copy allocated a fresh 32 KiB buffer per
// direction per session, 64 KiB of garbage for every short TLS session. The
// buffers now come from a pool and go back when the session ends.
func TestAnUnsplicedSessionReusesItsCopyBuffers(t *testing.T) {
	// Measured on one P with no collection: a GC empties sync.Pool, and a
	// buffer put back on one P waits in that P's private slot, which a Get on
	// another P cannot reach. Both are timing, not the property under test --
	// in production they cost an occasional allocation, not one per session.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	backend, stop := echoBackend(t)
	defer stop()
	pool := NewTCPBackendPool([]string{backend}, "round_robin", 10000, 1000, false)
	msg, buf := []byte("hello, backend"), make([]byte, len("hello, backend"))
	unsplicedSession(t, pool, msg, buf) // fills the pool

	const sessions = 32
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before) // stops the world and counts every allocation
	for range sessions {
		unsplicedSession(t, pool, msg, buf)
	}
	runtime.ReadMemStats(&after)
	perSession := (after.TotalAlloc - before.TotalAlloc) / sessions

	// Unpooled, a session allocates two 32 KiB buffers, 64 KiB and more;
	// with one direction pooled, 32 KiB and more. Pooled, it allocates about
	// 4 KiB of other things. Under the race detector sync.Pool drops a quarter
	// of what it is given, on purpose, so the bar there only separates pooled
	// from unpooled.
	bar := uint64(16 << 10)
	if raceDetector {
		bar = 48 << 10
	}
	if perSession >= bar {
		t.Fatalf("each unspliced session allocated %d bytes, want under %d: with pooled copy "+
			"buffers it no longer allocates 32 KiB per direction", perSession, bar)
	}
	t.Logf("%d bytes allocated per unspliced session", perSession)
}

// TestAPooledCopyBufferHoldsNoConnection: a buffer waiting in the pool must
// not reference the connections of the session that last used it, or an
// idle pool would keep closed sessions' sockets and TLS state reachable.
func TestAPooledCopyBufferHoldsNoConnection(t *testing.T) {
	// One P and no collection, so the next Get returns what the last session
	// Put (see TestAnUnsplicedSessionReusesItsCopyBuffers).
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	backend, stop := echoBackend(t)
	defer stop()
	pool := NewTCPBackendPool([]string{backend}, "round_robin", 10000, 1000, false)
	unsplicedSession(t, pool, []byte("x"), make([]byte, 1))

	cb, _ := copyBufs.Get().(*copyBuf)
	if cb == nil {
		t.Fatal("the session put no copy buffer back in the pool")
	}
	defer copyBufs.Put(cb)
	if cb.w.Writer != nil || cb.r.Reader != nil {
		t.Fatalf("a pooled copy buffer still references its last session's connections "+
			"(writer %T, reader %T)", cb.w.Writer, cb.r.Reader)
	}
}

// BenchmarkProxyTCPUnsplicedSession is one short session a TLS-terminating
// entrypoint would proxy, minus the handshake: an end splice cannot move.
func BenchmarkProxyTCPUnsplicedSession(b *testing.B) {
	backend, stop := echoBackend(b)
	defer stop()
	pool := NewTCPBackendPool([]string{backend}, "round_robin", 10000, 1000, false)
	msg, buf := make([]byte, 64), make([]byte, 64)
	b.ReportAllocs()
	for b.Loop() {
		unsplicedSession(b, pool, msg, buf)
	}
}
