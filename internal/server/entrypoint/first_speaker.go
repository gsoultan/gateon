// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Who speaks first on a plaintext TCP entrypoint. A client of a client-first
// protocol -- HTTP, TLS, SSH, RDP, PostgreSQL, Redis -- sends its opening
// bytes the moment it is connected, and they say where it goes. A client of a
// server-first protocol -- SMTP, POP3, IMAP, FTP, MySQL, VNC -- sends nothing
// until the server has greeted it, so only silence identifies it, and only the
// backend can end the silence.
//
// An entrypoint that serves nothing but a tcp route has nothing to tell apart:
// its connections go to the route the moment they are accepted. One that also
// serves HTTP, gRPC, ssh or rdp routes reads first, as below.
const (
	// serverFirstWait is how long a client may say nothing before the
	// entrypoint dials its tcp route's backend to see which of the two speaks
	// first. A server-first backend greets within a millisecond of being
	// dialled, so this is what a server-first session waits for its greeting
	// on such an entrypoint -- and what a client that speaks first, but late,
	// has before a server-first backend wins the race against it. Against a
	// backend that waits for its client, a late client loses nothing: its
	// bytes are routed as if it had spoken in time.
	//
	// Measured in network namespaces shaped with netem (curl, OpenSSL,
	// OpenSSH, Go's HTTP and TLS clients): opening bytes follow the
	// handshake's last ACK at once whatever the round-trip time, all read
	// within 11 ms of accept at 300 and 600 ms RTT. They come later behind a
	// slow uplink -- a full segment, Go's TLS ClientHello, 210 ms at 64
	// kbit/s; an HTTP request 25 ms -- or when their segment is lost and
	// resent: 280-310 ms later at 50 ms RTT, 610-660 ms at 200 ms. Half a
	// second covers a full segment down to ~25 kbit/s and one loss up to
	// ~150 ms RTT, and is half the second every silent client used to wait
	// before it was answered at all.
	serverFirstWait = 500 * time.Millisecond

	// silentLimit is how long a client of an entrypoint without a tcp route
	// -- nothing a silent client could be waiting for -- may say nothing
	// before it is told there is no route and closed. It is the second it
	// always had: such an entrypoint gains nothing from waiting less.
	silentLimit = time.Second

	// greetingBufSize bounds what is read of a backend's greeting before the
	// session starts; the rest follows through the session itself.
	greetingBufSize = 1024
)

// onlyTCPRouter is an L4Resolver that can tell when an entrypoint serves
// nothing but its tcp route.
type onlyTCPRouter interface {
	OnlyTCPRoute(ep *gateonv1.EntryPoint) l4.TCPProxy
}

// onlyTCPRoute returns ep's tcp route when it is all ep serves, else nil.
func onlyTCPRoute(ep *gateonv1.EntryPoint, deps *Deps) l4.TCPProxy {
	r, ok := deps.L4Resolver.(onlyTCPRouter)
	if !ok {
		return nil
	}
	return r.OnlyTCPRoute(ep)
}

// proxyUninspected hands a connection to the tcp route that is all its
// entrypoint serves, without reading a byte: a server-first backend greets it
// at once, and the proxy gets the socket itself, which it can splice.
func proxyUninspected(conn net.Conn, p l4.TCPProxy, ep *gateonv1.EntryPoint) {
	if debugLogging() {
		logger.L.LogDebug("TCP inspection: the tcp route is all this entrypoint serves, proxying",
			"ep", ep.Id, "remote", conn.RemoteAddr().String())
	}
	handleTCPProxyL4(conn, p)
}

// awaitFirstBytes returns the first bytes the client sends, to identify its
// protocol. A client silent for serverFirstWait on an entrypoint with a tcp
// route is raced against that route's backend (raceFirstSpeaker); on one
// without, it may speak until silentLimit, and first is empty if it does not.
// ok is false when the connection has been served or closed here.
func awaitFirstBytes(conn net.Conn, peek []byte, ep *gateonv1.EntryPoint, deps *Deps) (first []byte, ok bool) {
	n, err := readWithin(conn, peek, serverFirstWait)
	if n == 0 && err == nil {
		if sp := speculativeRoute(ep, deps); sp != nil {
			return raceFirstSpeaker(conn, peek, sp, raceTarget{ep: ep, limit: raceLimit(ep, deps)})
		}
		n, err = readWithin(conn, peek, silentLimit-serverFirstWait)
	}
	if err != nil {
		clientLeft(conn, ep, err)
		return nil, false
	}
	return peek[:n], true
}

// clientLeft closes a connection whose client hung up before it said
// anything -- a port scan, a TCP health probe -- which is routine. It was
// logged at ERROR, a line per connection that buried the errors worth reading.
func clientLeft(conn net.Conn, ep *gateonv1.EntryPoint, err error) {
	if debugLogging() {
		logger.L.LogDebug("TCP inspection: client left before sending", "ep", ep.Id, "error", err)
	}
	_ = conn.Close()
}

// readWithin reads the client's first bytes into peek, waiting at most window.
// A client that sent nothing in time reads as n == 0 with a nil error, and
// conn is left with no deadline, ready for whoever serves it next.
func readWithin(conn net.Conn, peek []byte, window time.Duration) (int, error) {
	_ = conn.SetReadDeadline(time.Now().Add(window))
	n, err := conn.Read(peek)
	_ = conn.SetReadDeadline(time.Time{})
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return 0, nil
	}
	return n, err
}

// speculativeRoute returns ep's generic tcp route when it can dial a backend
// before it is sure to use it -- every route the resolver builds can -- and
// nil when there is no such route.
func speculativeRoute(ep *gateonv1.EntryPoint, deps *Deps) l4.SpeculativeProxy {
	sp, _ := resolveTCPRoute(ep, deps, "").(l4.SpeculativeProxy)
	return sp
}

// raceLimit is how long a race may last with neither side speaking: the
// entrypoint's read timeout, the time any of its clients has to say what it
// wants -- here also the time a slow server-first backend has to greet.
func raceLimit(ep *gateonv1.EntryPoint, deps *Deps) time.Duration {
	read, _ := resolveEPTimeouts(ep.Id, ep, deps)
	return read
}

// raceTarget is what a race is run for: the entrypoint, and how long the race
// may last with neither side speaking.
type raceTarget struct {
	ep    *gateonv1.EntryPoint
	limit time.Duration
}

// speculation is what came of dialling the tcp route's backend for a silent
// client: the connection and what the backend said first, or why there is
// neither.
type speculation struct {
	backend l4.Backend
	dialed  bool
	first   []byte
	err     error
}

// discard closes the speculative backend connection, if one was made, unused.
func (s speculation) discard() {
	if s.dialed {
		s.backend.Close()
	}
}

// raceFirstSpeaker serves a client that has said nothing for serverFirstWait
// on an entrypoint that has a tcp route and something else to detect. It
// dials the route's backend and keeps reading the client, and whichever
// speaks first decides. A backend that greets first is a server-first
// protocol, and gets the session, greeting first. A client that speaks first
// -- a browser's request on a connection it opened ahead of time, a request
// whose first segment was lost and resent -- is routed by what it said, as if
// it had spoken in time, and the backend connection is closed unused: nothing
// a client sends reaches that backend unless routing chose it. first is what
// the client said; ok is false when the connection has been served or closed.
func raceFirstSpeaker(conn net.Conn, peek []byte, sp l4.SpeculativeProxy, rt raceTarget) (first []byte, ok bool) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan speculation, 1)
	// Set before the speculation starts: its wake-up moves this deadline to
	// now, and nothing may overwrite it until the speculation has returned.
	_ = conn.SetReadDeadline(time.Now().Add(rt.limit))
	go speculate(ctx, sp, conn, done)
	n, err := conn.Read(peek)
	cancel()
	s := <-done // joined: no goroutine or backend connection outlives the race
	_ = conn.SetReadDeadline(time.Time{})
	return settleRace(conn, rt.ep, raceResult{said: peek[:n], err: err, spec: s})
}

// speculate dials the backend for client and reads what it says first. When
// the backend speaks, or cannot be reached, it ends the client's wait -- the
// race is decided either way -- and when ctx is cancelled, because the client
// spoke or left, it stops dialling or reading at once.
func speculate(ctx context.Context, sp l4.SpeculativeProxy, client net.Conn, done chan<- speculation) {
	b, err := sp.DialBackend(ctx, client)
	if err != nil {
		if ctx.Err() == nil {
			_ = client.SetReadDeadline(time.Now())
		}
		done <- speculation{err: err}
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = b.SetReadDeadline(time.Now()) })
	buf := make([]byte, greetingBufSize)
	n, err := b.Read(buf)
	if stop() { // not cancelled: the backend's read ended on its own
		_ = client.SetReadDeadline(time.Now())
	}
	done <- speculation{backend: b, dialed: true, first: buf[:n], err: err}
}

// raceResult is how a race ended: what the client said, or why its read
// ended without it, and what came of the speculation.
type raceResult struct {
	said []byte
	err  error
	spec speculation
}

// settleRace acts on who spoke first. The client's bytes win whenever it has
// said anything, even when the backend spoke at the same moment.
func settleRace(conn net.Conn, ep *gateonv1.EntryPoint, r raceResult) ([]byte, bool) {
	switch {
	case len(r.said) > 0:
		r.spec.discard()
		logRace(ep, conn, "client spoke first, routing by its bytes")
		return r.said, true
	case r.err != nil && !errors.Is(r.err, os.ErrDeadlineExceeded):
		r.spec.discard()
		clientLeft(conn, ep, r.err)
	case len(r.spec.first) > 0:
		logRace(ep, conn, "backend spoke first, proxying")
		r.spec.backend.Proxy(conn, r.spec.first)
	default:
		// The backend could not be reached, or closed without a word, or
		// neither side spoke within the limit.
		r.spec.discard()
		logRace(ep, conn, "neither spoke, or the backend could not be reached; closing")
		_ = conn.Close()
	}
	return nil, false
}

// logRace records how a race ended, at DEBUG: one line per silent connection.
func logRace(ep *gateonv1.EntryPoint, conn net.Conn, outcome string) {
	if debugLogging() {
		logger.L.LogDebug("TCP inspection: "+outcome, "ep", ep.Id, "remote", conn.RemoteAddr().String())
	}
}
