// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
)

// spliceSessionBytes is what one session moves each way.
const spliceSessionBytes = 1 << 20

// TestProxyTCPSplicesAReadAheadConnection proves the kernel moves an inspected
// session's bytes, not a user-space buffer.
//
// SpliceCopy reaches splice(2) only when both ends are *net.TCPConn. The TCP
// entrypoint hands the proxy a wrapper -- it read the first bytes to identify
// the protocol -- so neither direction spliced: each fell back to io.Copy, which
// allocates a 32 KiB buffer and copies every byte into it and out again. The
// allocation is the observable: a session that splices both ways allocates no
// copy buffer at all, one that does not allocates 64 KiB.
func TestProxyTCPSplicesAReadAheadConnection(t *testing.T) {
	const sessions = 8
	// Every buffer is allocated before the measurement, one set per session:
	// the backend and the client run in different goroutines, and sharing a
	// buffer between them, or between sessions, is a data race.
	type buffers struct{ up, sink, down, got []byte }
	bufs := make([]buffers, sessions+1)
	for i := range bufs {
		bufs[i] = buffers{
			up:   make([]byte, spliceSessionBytes),
			sink: make([]byte, spliceSessionBytes+1), // the read-ahead byte and the upload
			down: make([]byte, spliceSessionBytes),
			got:  make([]byte, spliceSessionBytes),
		}
	}
	session := func(b buffers) {
		client, done := proxiedPair(t, "x", false, func(c net.Conn) {
			if _, err := io.ReadFull(c, b.sink); err != nil {
				return
			}
			_, _ = c.Write(b.down)
		})
		if _, err := client.Write(b.up); err != nil {
			t.Fatalf("upload: %v", err)
		}
		if _, err := io.ReadFull(client, b.got); err != nil {
			t.Fatalf("download: %v", err)
		}
		_ = client.Close()
		<-done
	}
	session(bufs[sessions]) // warm the pipe pool and the runtime's first-use allocations

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range sessions {
		session(bufs[i])
	}
	runtime.ReadMemStats(&after)

	perSession := (after.TotalAlloc - before.TotalAlloc) / sessions
	if perSession >= 32<<10 {
		t.Fatalf("each proxied session allocated %d bytes; a session spliced in both "+
			"directions allocates no copy buffer, and each direction that falls back to "+
			"io.Copy allocates 32 KiB", perSession)
	}
	t.Logf("%d bytes allocated per 2 MiB session", perSession)
}

// TestSplicedSessionsCountsTheSessionsBeingSpliced: the count the Diagnostics
// page shows is sessions whose bytes the kernel is moving now -- an inspected
// plaintext session counts, a session with an end that is not a plain TCP
// socket (a TLS connection, here a pipe) does not, and neither counts once it
// has ended.
func TestSplicedSessionsCountsTheSessionsBeingSpliced(t *testing.T) {
	echo := func(c net.Conn) { _, _ = io.Copy(c, c) }
	roundTrip := func(t *testing.T, c net.Conn) {
		t.Helper()
		if _, err := c.Write([]byte{1}); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			t.Fatalf("echo: %v", err)
		}
	}

	client, done := proxiedPair(t, "", false, echo)
	roundTrip(t, client) // the session is up
	if n := SplicedSessions(); n != 1 {
		t.Errorf("%d spliced sessions with one inspected plaintext session open, want 1", n)
	}
	_ = client.Close()
	<-done
	if n := SplicedSessions(); n != 0 {
		t.Errorf("%d spliced sessions after it ended, want 0", n)
	}

	backend := listenLoopback(t)
	echoed := make(chan struct{})
	go func() {
		defer close(echoed)
		if c, err := backend.Accept(); err == nil {
			echo(c)
			_ = c.Close()
		}
	}()
	defer func() {
		_ = backend.Close()
		<-echoed
	}()
	pipeClient, pipeProxySide := net.Pipe()
	pool := NewTCPBackendPool([]string{backend.Addr().String()}, "round_robin", 10000, 1000, false)
	proxied := make(chan struct{})
	go func() {
		defer close(proxied)
		pool.ProxyTCP(context.Background(), pipeProxySide)
	}()
	roundTrip(t, pipeClient)
	if n := SplicedSessions(); n != 0 {
		t.Errorf("%d spliced sessions with only a session whose client is not a TCP socket, want 0", n)
	}
	_ = pipeClient.Close()
	<-proxied
}
