// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
)

// A plaintext TCP entrypoint that finds HTTP on a connection hands it to a
// shared HTTP server and returns. The connection's slot -- max_connections
// (ADR 0032), the per-address cap and the block hook's reach (ADR 0036) -- was
// given back at that return, while the connection itself went on being served
// for as long as its client kept it alive: an entrypoint with max_connections
// 2 served twenty idle keep-alive connections at once, and a blocked
// address's open HTTP connection outlived the block. The slot is now held
// until the HTTP connection closes (ADR 0075).

// keepAliveExchange sends one keep-alive request on c and reports whether a
// response came back; c stays open for the next.
func keepAliveExchange(c net.Conn) bool {
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestHandedOffHTTPConnectionsHoldTheirTCPEntrypointSlots: with
// max_connections N, N idle keep-alive HTTP connections are served and every
// one past them is refused while they stay open; closing one frees its slot.
func TestHandedOffHTTPConnectionsHoldTheirTCPEntrypointSlots(t *testing.T) {
	const limit, extra = 2, 3
	deps := mockDepsForInspection(t)
	ep := tcpEntrypoint(t, "capped-http-over-tcp")
	ep.MaxConnections = limit
	e := runEntrypoint(t, ep, deps)

	held := make([]net.Conn, 0, limit)
	for i := range limit {
		c := dialBounded(t, e.addr)
		if !keepAliveExchange(c) {
			t.Fatalf("keep-alive connection %d of the %d the limit admits was not served", i+1, limit)
		}
		held = append(held, c)
	}
	served := 0
	for range extra {
		c := dialBounded(t, e.addr)
		if keepAliveExchange(c) {
			served++
		}
		_ = c.Close()
	}
	if served != 0 {
		t.Errorf("with %d keep-alive connections held open, %d of %d more were served "+
			"through an entrypoint with max_connections %d", limit, served, extra, limit)
	}

	_ = held[0].Close()
	admittedHTTPWithin(t, e.addr)
	_ = held[1].Close()
	e.drained(t)
}

// TestABlockClosesAnAddressOpenHandedOffHTTPConnection: an idle keep-alive
// HTTP connection served through a plaintext TCP entrypoint is closed when
// its address is blocked, as an L4 session is, instead of living on until its
// idle timeout or its next request.
func TestABlockClosesAnAddressOpenHandedOffHTTPConnection(t *testing.T) {
	const blocked = "198.51.100.141"
	withTelemetryStore(t)
	ep, deps := tcpEntrypoint(t, "block-open-http-over-tcp"), mockDepsForInspection(t)
	tcpEntrypointFrom(t, ep, deps, nil, blocked)

	c := dialBounded(t, ep.Address)
	if !keepAliveExchange(c) {
		t.Fatal("the keep-alive connection was not served before the block")
	}
	shun(t, blocked)
	if !closedWithin(t, c, sessionBound) {
		t.Errorf("the open HTTP connection from %s was not closed after its address was blocked", blocked)
	}
}

// TestADispatcherClosedWithConnectionsQueuedReleasesThem: a connection queued
// for the shared HTTP server when it shuts down is never accepted, so it is
// closed -- and its slot released -- by the dispatcher instead of held for
// ever.
func TestADispatcherClosedWithConnectionsQueuedReleasesThem(t *testing.T) {
	d := newSharedHTTPDispatcher(&net.TCPAddr{})
	released := make(chan struct{})
	lease := &connLease{end: func() { close(released) }}
	a, b := net.Pipe()
	t.Cleanup(func() { _ = b.Close() })
	d.conns <- lease.handOff(a)
	_ = d.Close()
	select {
	case <-released:
	default:
		t.Fatal("a connection still queued when the dispatcher closed kept its slot")
	}
	if _, err := b.Write([]byte("x")); err == nil {
		t.Error("the queued connection was not closed")
	}
}
