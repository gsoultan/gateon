// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/syncutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serverFirstGreeting is what a server-first backend says the moment it
// accepts, before its client has sent anything: SMTP's 220 line here. MySQL,
// POP3, IMAP, FTP and VNC servers open the same way, and their clients wait
// for it before they say a word.
const serverFirstGreeting = "220 mail.example.test ESMTP ready\r\n"

// greetThenEcho is a server-first backend: it greets, then echoes.
func greetThenEcho(c net.Conn) {
	if _, err := io.WriteString(c, serverFirstGreeting); err != nil {
		return
	}
	_, _ = io.Copy(c, c)
}

// sessionBound fails a read or write that has not completed long after it
// should have. It is a failure timeout, not a wait: every step it bounds
// finishes in about a second at most when the entrypoint behaves.
const sessionBound = 10 * time.Second

// dialBounded connects to addr with every later read and write bounded by
// sessionBound.
func dialBounded(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, sessionBound)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	_ = c.SetDeadline(time.Now().Add(sessionBound))
	return c
}

// runningEntrypoint is a plaintext TCP entrypoint started the way cmd/gateon
// starts one.
type runningEntrypoint struct {
	addr string
	reg  *ShutdownRegistry
	wg   *syncutil.WaitGroup
}

// mixedEntrypoint starts a plaintext TCP entrypoint whose HTTP server answers
// "inspected-http" and, when backend is not "", whose generic TCP route --
// resolved by the l4.Resolver cmd/gateon builds -- leads to backend.
func mixedEntrypoint(t *testing.T, backend string) *runningEntrypoint {
	t.Helper()
	deps := mockDepsForInspection(t)
	ep := tcpEntrypoint(t, "mixed-tcp")
	if backend != "" {
		deps.L4Resolver = l4Resolver(t, ep.Id, backend)
	}
	return runEntrypoint(ep, deps)
}

// tcpEntrypoint is a TCP entrypoint on a free loopback port.
func tcpEntrypoint(t *testing.T, id string) *gateonv1.EntryPoint {
	t.Helper()
	return &gateonv1.EntryPoint{
		Id:        id,
		Address:   freeAddr(t),
		Type:      gateonv1.EntryPoint_TCP,
		Protocols: []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
	}
}

// runEntrypoint starts ep with deps, the way cmd/gateon starts a TCP entrypoint.
func runEntrypoint(ep *gateonv1.EntryPoint, deps *Deps) *runningEntrypoint {
	e := &runningEntrypoint{addr: ep.Address, reg: deps.ShutdownRegistry, wg: &syncutil.WaitGroup{}}
	startTCPServer(e.addr, ep, deps, e.wg, e.reg) // binds before it returns
	return e
}

// drained fails the test unless every connection the entrypoint accepted had
// ended on its own -- its goroutine returned, its sockets closed -- by the time
// its clients were gone, and then stops it. A shutdown that had to force
// connections closed returns only once its deadline has passed.
func (e *runningEntrypoint) drained(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), sessionBound)
	defer cancel()
	e.reg.ShutdownAll(ctx)
	if ctx.Err() != nil {
		t.Errorf("a connection through the entrypoint was still open %v after its client had gone", sessionBound)
	}
	waitWithin(t, e.wg)
}

// TestAServerFirstBackendGreetsAClientThatWaitsForIt: a plaintext TCP
// entrypoint reads a connection's first bytes to choose between its HTTP
// server, an SSH or RDP route and its L4 route. A client of a server-first
// protocol sends nothing until it has the server's greeting, so the entrypoint
// waited for the client while the client waited for the server; after a second
// of silence the entrypoint wrote its own banner and hung up, and the backend
// was never dialled. SMTP, POP3, IMAP, FTP and MySQL could not be proxied
// through a plaintext TCP entrypoint at all.
func TestAServerFirstBackendGreetsAClientThatWaitsForIt(t *testing.T) {
	backend, stopBackend := serveBackend(t, greetThenEcho)
	defer stopBackend()
	e := mixedEntrypoint(t, backend)

	c := dialBounded(t, e.addr)
	r := bufio.NewReader(c)
	got, err := r.ReadString('\n')
	if err != nil || got != serverFirstGreeting {
		t.Fatalf("a client waiting for its server to speak first read %q (%v), want the backend's "+
			"greeting %q: the entrypoint waited for the client while the client waited for the server",
			got, err, serverFirstGreeting)
	}
	const command = "EHLO client.example.test\r\n"
	if _, err := io.WriteString(c, command); err != nil {
		t.Fatalf("write after the greeting: %v", err)
	}
	if echo, err := r.ReadString('\n'); err != nil || echo != command {
		t.Fatalf("after the greeting the backend echoed %q (%v), want %q: the session did not carry "+
			"the client's own bytes", echo, err, command)
	}
	_ = c.Close()
	e.drained(t)
}

// TestClientsThatSpeakFirstAreStillRoutedByWhatTheySay: handing silent clients
// to the TCP route must not change where a client that speaks first goes. On
// one entrypoint with both an HTTP server and a TCP route, an HTTP request is
// still answered by the HTTP server, and a TLS client -- which a plaintext
// entrypoint passes through, ClientHello first -- still completes its
// handshake with the backend behind the TCP route.
func TestClientsThatSpeakFirstAreStillRoutedByWhatTheySay(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	backend, stopBackend := serveBackend(t, func(c net.Conn) {
		tc := tls.Server(c, serverTLS)
		line, err := bufio.NewReader(tc).ReadString('\n')
		if err != nil {
			return
		}
		_, _ = io.WriteString(tc, "tls backend: "+line)
		_ = tc.Close()
	})
	defer stopBackend()
	e := mixedEntrypoint(t, backend)

	c := dialBounded(t, e.addr)
	if status := httpStatusLine(t, c); status != "HTTP/1.1 200 OK\r\n" {
		t.Errorf("an HTTP request answered %q, want the entrypoint's HTTP server's 200", status)
	}
	_ = c.Close()

	tc, err := tls.DialWithDialer(&net.Dialer{Timeout: sessionBound}, "tcp", e.addr, clientTLS)
	if err != nil {
		t.Fatalf("a TLS client could not complete its handshake through the TCP route: %v", err)
	}
	_ = tc.SetDeadline(time.Now().Add(sessionBound))
	if _, err := io.WriteString(tc, "hello\n"); err != nil {
		t.Fatalf("write over TLS: %v", err)
	}
	if got, err := bufio.NewReader(tc).ReadString('\n'); err != nil || got != "tls backend: hello\n" {
		t.Errorf("over TLS the backend answered %q (%v), want %q", got, err, "tls backend: hello\n")
	}
	_ = tc.Close()
	e.drained(t)
}

// httpStatusLine sends a GET on c and returns the first line of the answer.
func httpStatusLine(t *testing.T, c net.Conn) string {
	t.Helper()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: gw.example.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return line
}

// lateHTTPClient is how late the slow-client tests send their opening bytes:
// the time the delay is the point of, not a wait for something to happen.
// 350 ms is a full segment queued behind a ~35 kbit/s uplink, or the segment
// carrying the request lost once and retransmitted on a path of up to ~100 ms
// RTT -- what serverFirstWait is documented to cover.
const lateHTTPClient = 350 * time.Millisecond

// speakLate sends an HTTP request on c lateBy after it was connected, and
// returns the first line of the answer.
func speakLate(t *testing.T, c net.Conn, lateBy time.Duration) string {
	t.Helper()
	<-time.After(lateBy) // the client's slowness is the stimulus under test
	return httpStatusLine(t, c)
}

// TestAClientThatSpeaksLateButInsideTheWindowIsStillInspected: the window is
// what separates a slow client-first client from a server-first one. A client
// whose request arrives late, but inside it, must still reach the HTTP server;
// had the window been too short, it would have been proxied to the TCP route
// uninspected and read the backend's greeting.
func TestAClientThatSpeaksLateButInsideTheWindowIsStillInspected(t *testing.T) {
	if lateHTTPClient >= serverFirstWait {
		t.Fatalf("serverFirstWait is %v, no longer longer than the %v a slow client is documented to "+
			"be allowed", serverFirstWait, lateHTTPClient)
	}
	backend, stopBackend := serveBackend(t, greetThenEcho)
	defer stopBackend()
	e := mixedEntrypoint(t, backend)

	c := dialBounded(t, e.addr)
	if status := speakLate(t, c, lateHTTPClient); status != "HTTP/1.1 200 OK\r\n" {
		t.Errorf("an HTTP client %v late read %q, want the HTTP server's 200: it was taken for a "+
			"client waiting for the server", lateHTTPClient, status)
	}
	_ = c.Close()
	e.drained(t)
}

// TestAnEntrypointWithoutATCPRouteStillGivesASlowClientItsSecond: with no TCP
// route there is nothing a silent client could be waiting for, so the shorter
// window buys nothing, and an entrypoint serving only HTTP keeps the second
// every client had before to say something.
func TestAnEntrypointWithoutATCPRouteStillGivesASlowClientItsSecond(t *testing.T) {
	const lateBy = serverFirstWait + (silentLimit-serverFirstWait)/2
	e := mixedEntrypoint(t, "")

	c := dialBounded(t, e.addr)
	if status := speakLate(t, c, lateBy); status != "HTTP/1.1 200 OK\r\n" {
		t.Errorf("an HTTP client %v late read %q from an entrypoint with no TCP route, want the HTTP "+
			"server's 200", lateBy, status)
	}
	_ = c.Close()
	e.drained(t)
}

// TestASilentClientOfAnEntrypointWithoutATCPRouteIsToldSo: a client that never
// speaks to an entrypoint with no TCP route is answered and closed after its
// second, as before -- but the answer now says why, where it used to be the
// entrypoint's name and the time (whose String form ends in the monotonic
// clock reading: the process's uptime), and the DEBUG line says what
// happened, where it claimed a "fallback to generic TCP" that never existed.
func TestASilentClientOfAnEntrypointWithoutATCPRouteIsToldSo(t *testing.T) {
	logs := captureLogsAt(t, slog.LevelDebug) // before anything that logs starts
	e := mixedEntrypoint(t, "")

	c := dialBounded(t, e.addr)
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read %q, then %v: the entrypoint never closed a client it had no route for", got, err)
	}
	if string(got) != noRouteReply {
		t.Errorf("a silent client with no route for it read %q, want %q", got, noRouteReply)
	}
	_ = c.Close()
	e.drained(t)

	line := logLineWith(logs.String(), "remote="+c.LocalAddr().String())
	if !strings.Contains(line, `msg="TCP inspection: no route for this connection, closing it"`) ||
		!strings.Contains(line, "bytes=0") {
		t.Errorf("the silent unrouted client's DEBUG line does not say what happened to it: %q", line)
	}
}

// TestATLSEntrypointWithoutARouteSaysSo: an entrypoint that terminates TLS and
// has no route answers each connection with the line a plaintext one gives --
// over TLS -- where it used to give the entrypoint's name and the time.
func TestATLSEntrypointWithoutARouteSaysSo(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	deps := mockDepsForInspection(t)
	deps.TLSConfig = serverTLS
	ep := tcpEntrypoint(t, "tls-tcp")
	ep.Tls = &gateonv1.TlsConfig{Enabled: true}
	e := runEntrypoint(ep, deps)

	c, err := tls.DialWithDialer(&net.Dialer{Timeout: sessionBound}, "tcp", e.addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(sessionBound))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != noRouteReply {
		t.Errorf("a TLS client with no route for it read %q (%v), want %q", got, err, noRouteReply)
	}
	_ = c.Close()
	e.drained(t)
}

// logLineWith returns the last line of logs containing s.
func logLineWith(logs, s string) string {
	last := ""
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, s) {
			last = line
		}
	}
	return last
}

// TestATLSEntrypointCarriesAServerFirstSession: an entrypoint that terminates
// TLS does not inspect -- it has nothing readable to inspect before the
// handshake -- so it proxies at once, and the backend's greeting is what drives
// the server side of the handshake. It never had the plaintext entrypoint's
// problem; this pins that it still does not.
func TestATLSEntrypointCarriesAServerFirstSession(t *testing.T) {
	backend, stopBackend := serveBackend(t, greetThenEcho)
	defer stopBackend()
	serverTLS, clientTLS := selfSignedTLS(t)
	addr, stop := l4Entrypoint(t, backend, serverTLS)
	defer stop()

	c, err := tls.DialWithDialer(&net.Dialer{Timeout: sessionBound}, "tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(sessionBound))
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || got != serverFirstGreeting {
		t.Fatalf("over a TLS entrypoint a waiting client read %q (%v), want the greeting %q",
			got, err, serverFirstGreeting)
	}
}

// BenchmarkServerFirstSession is one server-first session per operation:
// connect, wait for the backend's greeting, one echo, close -- against the
// backend itself ("direct") and through a plaintext TCP entrypoint whose TCP
// route leads to it ("entrypoint"). The difference is what the entrypoint
// makes a server-first client wait for its greeting: serverFirstWait, in which
// the client proves it is not going to speak, and the backend dial.
func BenchmarkServerFirstSession(b *testing.B) {
	backend, stopBackend := serveBackend(b, greetThenEcho)
	defer stopBackend()
	addr, stop := plaintextTCPEntrypoint(b, backend)
	defer stop()
	b.Run("direct", func(b *testing.B) { benchServerFirstSession(b, backend) })
	b.Run("entrypoint", func(b *testing.B) { benchServerFirstSession(b, addr) })
}

func benchServerFirstSession(b *testing.B, addr string) {
	greeting := make([]byte, len(serverFirstGreeting))
	command := []byte("NOOP\r\n")
	echo := make([]byte, len(command))
	b.ReportAllocs()
	for b.Loop() {
		c, err := net.DialTimeout("tcp", addr, sessionBound)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		if _, err := io.ReadFull(c, greeting); err != nil || string(greeting) != serverFirstGreeting {
			b.Fatalf("greeting %q: %v", greeting, err)
		}
		if _, err := c.Write(command); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(c, echo); err != nil {
			b.Fatalf("echo: %v", err)
		}
		_ = c.Close()
	}
}
