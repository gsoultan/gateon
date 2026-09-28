// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// echoSession opens a session through addr and returns it once line has come
// back, which proves the session reached the backend.
func echoSession(t *testing.T, addr, line string) net.Conn {
	t.Helper()
	c := dialBounded(t, addr)
	if _, err := io.WriteString(c, line); err != nil {
		t.Fatalf("write %q: %v", line, err)
	}
	if _, err := io.ReadFull(c, make([]byte, len(line))); err != nil {
		t.Fatalf("echo of %q: %v", line, err)
	}
	return c
}

// refused reports whether the entrypoint closed c without proxying it: its
// first read ends without a byte of echo.
func refused(c net.Conn, line string) bool {
	_, _ = io.WriteString(c, line) // may already fail: the entrypoint can have closed it
	n, _ := c.Read(make([]byte, len(line)))
	return n == 0
}

// admittedWithin opens sessions through addr until one is admitted, and fails
// the test if none is by the bound. Each attempt is a real connection the
// entrypoint either refuses at once or proxies.
func admittedWithin(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(sessionBound)
	for time.Now().Before(deadline) {
		c := dialBounded(t, addr)
		if !refused(c, "again\n") {
			return c
		}
		_ = c.Close()
	}
	t.Fatalf("no session was admitted within %v of one ending: a finished session did not free its slot", sessionBound)
	return nil
}

// TestOpenConnsHoldsNoMoreThanItsLimit pins the accounting the limit rests on:
// the connection past the limit is refused, one that ends frees its slot for
// the next, and once shutdown has begun nothing is admitted at all.
func TestOpenConnsHoldsNoMoreThanItsLimit(t *testing.T) {
	o := newOpenConns(2)
	a, b, c := pipeEnd(t), pipeEnd(t), pipeEnd(t)
	if o.add(a) != admitted || o.add(b) != admitted {
		t.Fatal("the first two connections were not admitted under a limit of 2")
	}
	if got := o.add(c); got != refusedFull {
		t.Fatalf("a third connection under a limit of 2 was %v, want refusedFull", got)
	}
	o.remove(a)
	if got := o.add(c); got != admitted {
		t.Fatalf("after one of two connections ended, the next was %v, want admitted", got)
	}
	o.remove(b)
	o.remove(c)
	o.shutdown(t.Context())
	if got := o.add(a); got != refusedClosing {
		t.Fatalf("a connection after shutdown began was %v, want refusedClosing", got)
	}
}

// pipeEnd is a connection to stand in for an accepted one.
func pipeEnd(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a
}

// TestATCPEntrypointRefusesConnectionsBeyondItsLimit: a TCP entrypoint's
// max_connections was stored, shown and read by nothing, so an L4 route had no
// cap at all -- a flood of connections, each costing the client a SYN, cost
// the gateway two goroutines and six descriptors apiece without bound. Past
// the limit a connection is now closed as soon as it is accepted, the
// backend never sees it, and a session that ends frees its slot.
func TestATCPEntrypointRefusesConnectionsBeyondItsLimit(t *testing.T) {
	var sessions atomic.Int32
	firstDone := make(chan struct{})
	backend, stopBackend := serveBackend(t, func(c net.Conn) {
		n := sessions.Add(1)
		_, _ = io.Copy(c, c)
		if n == 1 {
			close(firstDone)
		}
	})
	t.Cleanup(stopBackend)
	deps := mockDepsForInspection(t)
	ep := tcpEntrypoint(t, "capped-tcp")
	ep.MaxConnections = 2
	deps.L4Resolver = l4Resolver(t, ep.Id, backend)
	e := runEntrypoint(t, ep, deps)

	first, second := echoSession(t, e.addr, "one\n"), echoSession(t, e.addr, "two\n")
	third := dialBounded(t, e.addr)
	if !refused(third, "three\n") {
		t.Errorf("a third session through an entrypoint with max_connections 2 was proxied")
	}
	_ = third.Close()
	if n := sessions.Load(); n != 2 {
		t.Errorf("the backend saw %d sessions, want the 2 the limit admits", n)
	}

	_ = first.Close()
	select {
	case <-firstDone: // the first session's backend end is closed; its slot is being freed
	case <-time.After(sessionBound):
		t.Fatal("the first session never ended after its client closed")
	}
	fourth := admittedWithin(t, e.addr)
	_ = fourth.Close()
	_ = second.Close()
	e.drained(t)
}
