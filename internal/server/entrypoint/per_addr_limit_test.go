// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"net"
	"sync/atomic"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// EntryPointMaxConnections bounds what a flood of connections costs the gateway;
// it does not bound who pays, so one client could fill an entrypoint by itself.
// A per-address cap is the tighter, complementary bound: a connection past it is
// refused at accept, without blocking the loop, and loopback and the allowlist
// are exempt so a local proxy is not capped by the one address it shares
// (ADR 0036).

// trackConn records whether it has been closed, so a test can prove a
// connection past the cap was closed at accept.
type trackConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// fromAddr wraps a stand-in connection so it appears to come from ip, and lets
// a test see whether it was closed.
func fromAddr(t *testing.T, ip string) net.Conn {
	t.Helper()
	return peerConn{Conn: &trackConn{Conn: pipeEnd(t)}, peer: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
}

// closedConn reports whether the connection fromAddr made has been closed.
func closedConn(c net.Conn) bool {
	pc, ok := c.(peerConn)
	if !ok {
		return false
	}
	tc, ok := pc.Conn.(*trackConn)
	return ok && tc.closed.Load()
}

// TestPerAddrLimiterCountsPerAddress pins the accounting the caps rest on: a
// slot per address up to the limit, released when a connection closes, and an
// exempt address never counted at all.
func TestPerAddrLimiterCountsPerAddress(t *testing.T) {
	p := newPerAddrLimiter(2)
	const a, b = "203.0.113.9", "203.0.113.10"
	first, second := p.acquire(a), p.acquire(a)
	if !first || !second {
		t.Fatal("two connections from one address were not admitted under a per-address cap of 2")
	}
	if p.acquire(a) {
		t.Fatal("a third connection from the same address was admitted under a cap of 2")
	}
	if !p.acquire(b) {
		t.Fatal("a connection from a different address was refused: the cap is per address, not shared")
	}
	p.release(a)
	if !p.acquire(a) {
		t.Fatal("after one of the address's connections closed, the next was refused: the slot was not freed")
	}
	// Loopback is exempt: any number succeeds, and none is tracked, so the map
	// never grows for it.
	for range 5 {
		if !p.acquire("127.0.0.1") {
			t.Fatal("a loopback connection was capped per address")
		}
	}
	if _, tracked := p.counts["127.0.0.1"]; tracked {
		t.Error("an exempt address was counted in the per-address map")
	}
}

// TestNilPerAddrLimiterAdmitsEverything: the cap disabled (limit <= 0) is a nil
// limiter, which admits every connection and holds no state.
func TestNilPerAddrLimiterAdmitsEverything(t *testing.T) {
	if newPerAddrLimiter(0) != nil || newPerAddrLimiter(-1) != nil {
		t.Fatal("a non-positive per-address limit must disable the cap (nil limiter)")
	}
	var p *perAddrLimiter
	for range 3 {
		if !p.acquire("203.0.113.1") {
			t.Fatal("a nil per-address limiter refused a connection")
		}
	}
	p.release("203.0.113.1") // must not panic
}

// TestOpenConnsCapsPerAddress: a TCP entrypoint's connection set refuses a
// connection from an address already holding its per-address limit, admits one
// from another address (the entrypoint-wide slots are free), and frees the
// address's slot when a connection closes.
func TestOpenConnsCapsPerAddress(t *testing.T) {
	o := newOpenConns(100, newPerAddrLimiter(2))
	const a, b = "203.0.113.21", "203.0.113.22"
	x1, x2, x3 := fromAddr(t, a), fromAddr(t, a), fromAddr(t, a)
	if o.add(x1) != admitted || o.add(x2) != admitted {
		t.Fatal("the first two connections from one address were not admitted under a per-address cap of 2")
	}
	if got := o.add(x3); got != refusedPerAddr {
		t.Fatalf("a third connection from the same address was %v, want refusedPerAddr", got)
	}
	if got := o.add(fromAddr(t, b)); got != admitted {
		t.Fatalf("a connection from a different address was %v, want admitted", got)
	}
	o.remove(x1)
	if got := o.add(x3); got != admitted {
		t.Fatalf("after one of the address's connections closed, the next was %v, want admitted", got)
	}
}

// TestCappedListenerCapsPerAddress: the HTTP entrypoint's listener wrapper
// closes a connection accepted from an address already holding its per-address
// limit, counts it with the other connection-limit rejections, and goes on to
// the next connection -- the accept loop is not blocked -- while a connection
// from a different address is admitted.
func TestCappedListenerCapsPerAddress(t *testing.T) {
	const a, b = "203.0.113.31", "203.0.113.32"
	held1, held2 := fromAddr(t, a), fromAddr(t, a)
	overCap := fromAddr(t, a)
	other := fromAddr(t, b)
	l := &cappedListener{
		Listener: scriptListener(held1, held2, overCap, other),
		slots:    newConnSlots(&gateonv1.EntryPoint{Id: "peraddr-http", MaxConnections: 100}),
		perAddr:  newPerAddrLimiter(2),
	}

	c1 := acceptOne(t, l)
	_ = acceptOne(t, l)
	before := inflightRejections()
	// The third from a is over the per-address cap: Accept closes it and loops
	// on to the fourth, from b, which it returns.
	c4 := acceptOne(t, l)
	if got := c4.(*slotConn).addr; got != b {
		t.Fatalf("Accept returned a connection from %q; want the one past the cap skipped and %q returned", got, b)
	}
	if !closedConn(overCap) {
		t.Error("the connection past the per-address cap was not closed")
	}
	if got := inflightRejections() - before; got != 1 {
		t.Errorf("the per-address refusal was counted %d times with the connection-limit rejections, want 1", got)
	}
	// Closing one of a's connections frees its per-address slot (and the wide
	// slot it also held): a new connection from a is admitted again.
	_ = c1.Close()
	if !l.perAddr.acquire(a) {
		t.Error("after a connection from the address closed, its per-address slot was not freed")
	}
}

// TestATCPEntrypointCapsConnectionsPerSourceAddress drives the whole path: with
// GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR set to 2, two concurrent connections from
// one address are proxied, the third from it is closed at accept and counted,
// and a connection from a different address is served meanwhile -- the accept
// loop advanced past the refusal.
func TestATCPEntrypointCapsConnectionsPerSourceAddress(t *testing.T) {
	t.Setenv("GATEON_ENTRYPOINT_MAX_CONN_PER_ADDR", "2")
	const a, b = "198.51.100.201", "198.51.100.202"
	backend, sessions := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "peraddr-e2e"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	// Two from a (held), a third from a (refused), then b (served).
	tcpEntrypointFrom(t, ep, deps, nil, a, a, a, b)

	one := echoSession(t, ep.Address, "a1\n")
	two := echoSession(t, ep.Address, "a2\n")

	before := inflightRejections()
	third := dialBounded(t, ep.Address)
	if !refused(third, "a3\n") {
		t.Errorf("a third concurrent connection from %s under a per-address cap of 2 was served", a)
	}
	_ = third.Close()
	if got := inflightRejections() - before; got != 1 {
		t.Errorf("the per-address refusal was counted %d times with the connection-limit rejections, want 1", got)
	}

	// A connection from a different address is served: the loop was not blocked
	// by the refusal.
	_ = echoed(t, dialBounded(t, ep.Address), "b1\n")
	if n := sessions.Load(); n != 3 {
		t.Errorf("the backend saw %d sessions, want the 2 from %s plus 1 from %s", n, a, b)
	}
	_, _ = one, two
}

// scriptListener returns conns in order, then behaves as a closed listener
// (net.ErrClosed) once they are exhausted.
func scriptListener(conns ...net.Conn) net.Listener {
	ch := make(chan net.Conn, len(conns))
	for _, c := range conns {
		ch <- c
	}
	close(ch)
	return &scriptedListener{ch: ch}
}

type scriptedListener struct{ ch chan net.Conn }

func (l *scriptedListener) Accept() (net.Conn, error) {
	if c, ok := <-l.ch; ok {
		return c, nil
	}
	return nil, net.ErrClosed
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

// acceptOne accepts one connection from l and fails the test if it errors.
func acceptOne(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return c
}
