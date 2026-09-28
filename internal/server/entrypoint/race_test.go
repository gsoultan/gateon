// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

// silentBackend is a tcp route's backend that waits for its client and never
// speaks -- PostgreSQL, Redis, a TLS server. It reports each connection it
// accepts, and then how many bytes reached it before that connection closed.
type silentBackend struct {
	accepted chan struct{}
	received chan int64
}

func newSilentBackend(t *testing.T) (b *silentBackend, addr string, stop func()) {
	t.Helper()
	b = &silentBackend{accepted: make(chan struct{}, 4), received: make(chan int64, 4)}
	addr, stop = serveBackend(t, func(c net.Conn) {
		b.accepted <- struct{}{}
		n, _ := io.Copy(io.Discard, c)
		b.received <- n
	})
	return b, addr, stop
}

// wasAsked fails the test unless the entrypoint dialled the backend.
func (b *silentBackend) wasAsked(t *testing.T) {
	t.Helper()
	select {
	case <-b.accepted:
	case <-time.After(sessionBound):
		t.Fatal("the entrypoint never dialled its tcp route's backend for a client that said nothing")
	}
}

// closedUntouched fails the test unless the backend connection was closed
// with not one byte of the client's having reached it.
func (b *silentBackend) closedUntouched(t *testing.T) {
	t.Helper()
	select {
	case n := <-b.received:
		if n != 0 {
			t.Errorf("%d bytes reached the tcp route's backend, which routing never chose", n)
		}
	case <-time.After(sessionBound):
		t.Fatal("the speculative backend connection was never closed")
	}
}

// TestAClientThatConnectsAheadAndAsksLaterReachesTheHTTPRoute: a browser opens
// a connection before it has a request for it -- a speculative preconnect --
// and says nothing until it does. On an entrypoint serving HTTP beside a tcp
// route, that silence looked like a server-first client's: after the window
// the connection was handed to the tcp route, and the request, when it came,
// landed on that backend. Now the backend is only asked whether it speaks
// first; this one waits for its client, so the browser speaks first, is
// routed by what it says, and the backend connection is closed untouched.
func TestAClientThatConnectsAheadAndAsksLaterReachesTheHTTPRoute(t *testing.T) {
	const preconnectIdle = 700 * time.Millisecond
	backend, addr, stopBackend := newSilentBackend(t)
	t.Cleanup(stopBackend)
	e := mixedEntrypoint(t, addr)

	c := dialBounded(t, e.addr)
	if status := speakLate(t, c, preconnectIdle); status != "HTTP/1.1 200 OK\r\n" {
		t.Errorf("a request sent %v after its connection opened read %q, want the HTTP route's 200",
			preconnectIdle, status)
	}
	_ = c.Close()
	backend.wasAsked(t)
	backend.closedUntouched(t)
	e.drained(t)
}

// TestAClientThatSpeaksWhileTheBackendIsAskedIsRoutedByWhatItSaid is the race
// at the moment it is decided: the window has passed, the tcp route's backend
// has been dialled and has not spoken -- when a request whose first segment
// was lost and resent arrives -- and the client speaks. Its bytes decide.
func TestAClientThatSpeaksWhileTheBackendIsAskedIsRoutedByWhatItSaid(t *testing.T) {
	backend, addr, stopBackend := newSilentBackend(t)
	t.Cleanup(stopBackend)
	e := mixedEntrypoint(t, addr)

	c := dialBounded(t, e.addr)
	backend.wasAsked(t) // the barrier: the race is on
	if status := httpStatusLine(t, c); status != "HTTP/1.1 200 OK\r\n" {
		t.Errorf("a request sent while the tcp backend was being asked read %q, want the HTTP route's 200", status)
	}
	_ = c.Close()
	backend.closedUntouched(t)
	e.drained(t)
}

// TestATCPOnlyEntrypointGreetsWithoutAWindow: an entrypoint whose only route
// is a tcp route has nothing to tell apart, so it hands each connection to
// the route as it is accepted -- the backend greets at once -- and everything
// the client sends, HTTP included, is the backend's.
func TestATCPOnlyEntrypointGreetsWithoutAWindow(t *testing.T) {
	backend, stopBackend := serveBackend(t, greetThenEcho)
	t.Cleanup(stopBackend)
	e := tcpOnlyEntrypoint(t, backend)

	start := time.Now()
	c := dialBounded(t, e.addr)
	r := bufio.NewReader(c)
	got, err := r.ReadString('\n')
	if elapsed := time.Since(start); err != nil || got != serverFirstGreeting || elapsed >= serverFirstWait/5 {
		t.Fatalf("read %q (%v) %v after connecting, want the greeting well inside the %v window: "+
			"an entrypoint with nothing to detect must not wait to detect it", got, err, elapsed, serverFirstWait)
	}
	const request = "GET / HTTP/1.1\r\n"
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	if echo, err := r.ReadString('\n'); err != nil || echo != request {
		t.Errorf("the tcp backend echoed %q (%v), want the HTTP request line: on a tcp-only entrypoint "+
			"it is the backend's", echo, err)
	}
	_ = c.Close()
	e.drained(t)
}

// TestASilentClientAndASilentBackendAreBothClosedAtTheLimit: when neither side
// of the race speaks -- a connection opened and abandoned, against a backend
// that waits for its client -- both are closed once the entrypoint's read
// timeout has passed, and nothing is left open.
func TestASilentClientAndASilentBackendAreBothClosedAtTheLimit(t *testing.T) {
	backend, addr, stopBackend := newSilentBackend(t)
	t.Cleanup(stopBackend)
	ep := tcpEntrypoint(t, "race-limit")
	ep.ReadTimeoutMs = 300
	e := entrypointServing(t, ep, addr, true)

	c := dialBounded(t, e.addr)
	if got, err := io.ReadAll(c); err != nil || len(got) != 0 {
		t.Errorf("a client that never spoke read %q (%v), want its connection closed without a word", got, err)
	}
	_ = c.Close()
	backend.wasAsked(t)
	backend.closedUntouched(t)
	e.drained(t)
}

// TestASilentClientWhoseTCPBackendIsDownIsClosedPromptly: when the backend a
// silent client would be raced against cannot be reached, the race is over
// -- nothing can greet the client -- and it is closed then, as a session whose
// backend refuses has always been, not left waiting for the read timeout.
func TestASilentClientWhoseTCPBackendIsDownIsClosedPromptly(t *testing.T) {
	ep := tcpEntrypoint(t, "dead-backend")
	ep.ReadTimeoutMs = int32(sessionBound.Milliseconds()) // the limit is not what may close it
	e := entrypointServing(t, ep, freeAddr(t), true)      // nothing listens there

	start := time.Now()
	c := dialBounded(t, e.addr)
	got, err := io.ReadAll(c)
	if elapsed := time.Since(start); err != nil || len(got) != 0 || elapsed >= sessionBound/2 {
		t.Errorf("a silent client whose tcp backend is down read %q (%v) and was closed after %v, "+
			"want closed soon after the %v window", got, err, elapsed, serverFirstWait)
	}
	_ = c.Close()
	e.drained(t)
}
