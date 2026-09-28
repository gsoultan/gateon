// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A TCP entrypoint did not read the IP mitigation list. An address shunned
// automatically or blocked by hand was refused by every HTTP entrypoint
// (IPMitigation) and, where eBPF ran, dropped in the kernel -- and connected
// to a TCP entrypoint without eBPF as freely as any other: to an SSH, database
// or mail backend, and on a tcp-only entrypoint to the backend directly, where
// an HTTP scanner never meets the HTTP chain at all. ADR 0032.

// peersListener makes each connection it accepts appear to come from the next
// of peers, in turn. A test can only connect from loopback, which the list
// exempts, and the address is all the check reads; everything else about the
// connection -- the socket, TLS, the route, the backend -- is real.
type peersListener struct {
	net.Listener
	mu    sync.Mutex
	peers []string
}

func (l *peersListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	peer := l.peers[0]
	if len(l.peers) > 1 {
		l.peers = l.peers[1:]
	}
	return peerConn{Conn: c, peer: &net.TCPAddr{IP: net.ParseIP(peer), Port: 40000}}, nil
}

type peerConn struct {
	net.Conn
	peer net.Addr
}

func (c peerConn) RemoteAddr() net.Addr { return c.peer }

// tcpEntrypointFrom starts ep the way cmd/gateon starts a TCP entrypoint, with
// its connections appearing to come from peers, and blocked, when it is not
// nil, standing in for the IP mitigation list's lookup.
func tcpEntrypointFrom(t *testing.T, ep *gateonv1.EntryPoint, deps *Deps, blocked func(string) bool, peers ...string) {
	t.Helper()
	wg := &syncutil.WaitGroup{}
	s := newTCPServer(ep, deps, wg)
	if blocked != nil {
		s.blocked = blocked
	}
	l, err := s.listen(ep.Address)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.start(&peersListener{Listener: l, peers: peers}, deps.ShutdownRegistry)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sessionBound)
		defer cancel()
		deps.ShutdownRegistry.ShutdownAll(ctx)
		wg.Wait()
	})
}

func shun(t *testing.T, ip string) {
	t.Helper()
	if err := telemetry.MarkIPMitigated(ip, "test: on the IP mitigation list"); err != nil {
		t.Fatalf("shun %s: %v", ip, err)
	}
}

// countingEcho is an echo backend that counts the sessions it is given.
func countingEcho(t *testing.T) (addr string, sessions *atomic.Int32) {
	t.Helper()
	sessions = &atomic.Int32{}
	addr, stop := serveBackend(t, func(c net.Conn) {
		sessions.Add(1)
		_, _ = io.Copy(c, c)
	})
	t.Cleanup(stop)
	return addr, sessions
}

// tcpEntrypointKind is one of the three ways a TCP entrypoint serves a
// connection, set up in front of backend.
type tcpEntrypointKind struct {
	name  string
	setup func(t *testing.T, backend string) (*gateonv1.EntryPoint, *Deps, func(net.Conn) net.Conn)
}

var tcpEntrypointKinds = []tcpEntrypointKind{
	{"plaintext, inspected", func(t *testing.T, backend string) (*gateonv1.EntryPoint, *Deps, func(net.Conn) net.Conn) {
		ep, deps := tcpEntrypoint(t, "blocklist-mixed"), mockDepsForInspection(t)
		deps.L4Resolver = l4Resolver(t, ep.Id, backend) // a tcp route beside an HTTP one: every connection is read
		return ep, deps, func(c net.Conn) net.Conn { return c }
	}},
	{"plaintext, tcp-only", func(t *testing.T, backend string) (*gateonv1.EntryPoint, *Deps, func(net.Conn) net.Conn) {
		ep, deps := tcpEntrypoint(t, "blocklist-tcp-only"), mockDepsForInspection(t)
		deps.L4Resolver = routesResolver(t, ep.Id, backend, false) // proxied at accept, never read
		return ep, deps, func(c net.Conn) net.Conn { return c }
	}},
	{"TLS-terminating", func(t *testing.T, backend string) (*gateonv1.EntryPoint, *Deps, func(net.Conn) net.Conn) {
		serverTLS, clientTLS := selfSignedTLS(t)
		ep, deps := tcpEntrypoint(t, "blocklist-tls"), mockDepsForInspection(t)
		ep.Tls = &gateonv1.TlsConfig{Enabled: true}
		deps.TLSConfig = serverTLS
		deps.L4Resolver = l4Resolver(t, ep.Id, backend)
		return ep, deps, func(c net.Conn) net.Conn { return tls.Client(c, clientTLS) }
	}},
}

// TestAShunnedAddressIsRefusedByEveryTCPEntrypoint: a connection from an
// address on the IP mitigation list is closed before a byte is read or a
// handshake made, on every kind of TCP entrypoint; its backend never sees it;
// and the refusal is recorded as the HTTP path records one. An address not on
// the list, through the same entrypoint, is served.
func TestAShunnedAddressIsRefusedByEveryTCPEntrypoint(t *testing.T) {
	const shunned, clean = "198.51.100.61", "198.51.100.62"
	for _, kind := range tcpEntrypointKinds {
		t.Run(kind.name, func(t *testing.T) {
			withTelemetryStore(t)
			shun(t, shunned)
			backend, sessions := countingEcho(t)
			ep, deps, client := kind.setup(t, backend)
			tcpEntrypointFrom(t, ep, deps, nil, shunned, clean)

			if !refused(client(dialBounded(t, ep.Address)), "from a shunned address\n") {
				t.Errorf("a connection from shunned %s was served", shunned)
			}
			if n := sessions.Load(); n != 0 {
				t.Errorf("the backend was given %d sessions from the shunned address, want 0", n)
			}
			_ = echoed(t, client(dialBounded(t, ep.Address)), "from a clean address\n")
			if n := refusalsRecordedFor(t, shunned); n != 1 {
				t.Errorf("%d ip_mitigation threats were recorded for %s's refused connection, want 1", n, shunned)
			}
		})
	}
}

// echoed writes line on c and fails the test unless it comes back.
func echoed(t *testing.T, c net.Conn, line string) net.Conn {
	t.Helper()
	if _, err := io.WriteString(c, line); err != nil {
		t.Fatalf("write %q: %v", line, err)
	}
	if _, err := io.ReadFull(c, make([]byte, len(line))); err != nil {
		t.Fatalf("the session was not served: the echo of %q: %v", line, err)
	}
	return c
}

// refusalsRecordedFor is how many ip_mitigation threats the store holds from ip.
func refusalsRecordedFor(t *testing.T, ip string) int {
	t.Helper()
	telemetry.FlushThreats()
	n := 0
	for _, th := range telemetry.GetSecurityThreatsLite(t.Context(), 1000, 0, nil) {
		if th.SourceIP == ip && th.Type == "ip_mitigation" {
			n++
		}
	}
	return n
}

// TestAnExemptShunnedAddressIsServedByATCPEntrypoint: the list's exemptions
// are the HTTP path's -- the one rule, identity.AddressBlocked -- so an
// address GATEON_MITIGATION_ALLOWLIST names is served although it is on the
// list, and so is one an operator has released.
func TestAnExemptShunnedAddressIsServedByATCPEntrypoint(t *testing.T) {
	const allowlisted, released = "198.51.100.71", "198.51.100.72"
	withTelemetryStore(t)
	shun(t, allowlisted)
	shun(t, released)
	if err := telemetry.MarkIPUnmitigated(released); err != nil {
		t.Fatalf("release %s: %v", released, err)
	}
	mitigation.SetAllowlist(mitigation.ParseAllowlist(allowlisted + "/32"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	backend, sessions := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "blocklist-exempt"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	tcpEntrypointFrom(t, ep, deps, nil, allowlisted, released)

	_ = echoed(t, dialBounded(t, ep.Address), "allowlisted\n")
	_ = echoed(t, dialBounded(t, ep.Address), "released\n")
	if n := sessions.Load(); n != 2 {
		t.Errorf("the backend was given %d sessions, want the allowlisted and the released address's 2", n)
	}
}

// BenchmarkTCPEntrypointBlockListCheck is what the check adds to each
// connection a TCP entrypoint accepts and serves: its client's address and one
// lookup on the list, for a client the list's cache has an answer for -- the
// steady state. A client it has not seen costs a database query once, and is
// cached after. The session benchmarks cannot resolve this against the noise
// of a loopback connection; this measures it alone.
func BenchmarkTCPEntrypointBlockListCheck(b *testing.B) {
	withTelemetryStore(b)
	s := &tcpServer{ep: &gateonv1.EntryPoint{Id: "bench"}, blocked: identity.AddressBlocked}
	var c net.Conn = peerConn{peer: &net.TCPAddr{IP: net.ParseIP("198.51.100.90"), Port: 40000}}
	if s.refuseBlocked(c) { // the first lookup reads the database, and caches its answer
		b.Fatal("a client not on the list was refused")
	}
	b.ReportAllocs()
	for b.Loop() {
		s.refuseBlocked(c)
	}
}

// TestASlowBlockListLookupHoldsUpNoOtherConnection: the list is read from the
// database when its cache has no answer for an address, so the lookup runs on
// the connection's own goroutine. While one connection's lookup waits, the
// next connection is accepted, looked up and served.
func TestASlowBlockListLookupHoldsUpNoOtherConnection(t *testing.T) {
	const slow, fast = "198.51.100.81", "198.51.100.82"
	entered, release := make(chan struct{}), make(chan struct{})
	var answer sync.Once
	lookup := func(ip string) bool {
		if ip == slow {
			close(entered)
			<-release
		}
		return false
	}
	backend, _ := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "blocklist-slow"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	tcpEntrypointFrom(t, ep, deps, lookup, slow, fast)
	// Runs before the entrypoint is stopped: a lookup still waiting would
	// keep the goroutine that asked it, and the shutdown with it, waiting too.
	t.Cleanup(func() { answer.Do(func() { close(release) }) })

	waiting := dialBounded(t, ep.Address)
	select {
	case <-entered: // the first connection's lookup has begun, and waits
	case <-time.After(sessionBound):
		t.Fatalf("no connection's client was looked up on the IP mitigation list within %v", sessionBound)
	}
	_ = echoed(t, dialBounded(t, ep.Address), "not held up\n")
	answer.Do(func() { close(release) })
	_ = echoed(t, waiting, "served once its lookup answered\n")
}
