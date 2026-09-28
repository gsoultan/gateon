// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// An HTTP entrypoint's max_connections was read by nothing: only TCP
// entrypoints honoured it (ADR 0032). An HTTP entrypoint held as many
// connections as clients cared to open -- idle keep-alive ones for a minute
// each, a slow client's for ten seconds before it sent a header -- each a
// goroutine, buffers and a descriptor paid for by the gateway alone.

// httpEntrypointFor starts ep, an HTTP entrypoint, the way cmd/gateon starts
// one, and returns the address it listens on. It is shut down when the test
// ends.
func httpEntrypointFor(t *testing.T, ep *gateonv1.EntryPoint, deps *Deps) string {
	t.Helper()
	capture := &addrCapture{addrs: make(chan net.Addr, 1)}
	deps.Phantom = capture
	wg := &syncutil.WaitGroup{}
	(&httpRunner{}).Run(context.Background(), ep, deps, wg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sessionBound)
		defer cancel()
		deps.ShutdownRegistry.ShutdownAll(ctx)
		wg.Wait()
	})
	select {
	case a := <-capture.addrs:
		return a.String()
	case <-time.After(sessionBound):
		t.Fatal("the HTTP entrypoint never listened")
		return ""
	}
}

// cappedHTTPEntrypoint starts a plaintext HTTP entrypoint holding at most max
// connections, whose every request is answered 200.
func cappedHTTPEntrypoint(t *testing.T, maxConns int32) string {
	t.Helper()
	ep := &gateonv1.EntryPoint{Id: "capped-http", Address: "127.0.0.1:0",
		Type: gateonv1.EntryPoint_HTTP, MaxConnections: maxConns}
	return httpEntrypointFor(t, ep, mockDepsForInspection(t))
}

// keptAlive opens a connection to addr, completes one HTTP/1.1 request on it
// and returns it open and idle, as a browser leaves one between requests.
func keptAlive(t *testing.T, addr string) net.Conn {
	t.Helper()
	c := dialBounded(t, addr)
	if code := getOn(t, c); code != http.StatusOK {
		t.Fatalf("a request on a connection the entrypoint admitted got %d, want 200", code)
	}
	return c
}

// getOn sends one keep-alive GET on c and returns its status, or 0 when the
// connection ended without a response.
func getOn(t *testing.T, c net.Conn) int {
	t.Helper()
	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// refusedHTTP reports whether the entrypoint closed a fresh connection to addr
// without answering its request. A refusal is prompt: the entrypoint closes
// the connection as it accepts it, so a read that is still waiting when the
// connection's bound passes -- a connection left queued behind a full
// entrypoint -- fails the test instead of counting as refused.
func refusedHTTP(t *testing.T, addr string) bool {
	t.Helper()
	c := dialBounded(t, addr)
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	n, err := c.Read(make([]byte, 1))
	if timedOut(err) {
		t.Fatalf("a connection past the limit was neither served nor closed within %v: "+
			"it waited for a slot, and so does every connection accepted after it", sessionBound)
	}
	return n == 0
}

// admittedHTTPWithin opens connections to addr until one is served, failing
// the test if none is by the bound: a connection that closed frees its slot
// once the server has seen it close.
func admittedHTTPWithin(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(sessionBound)
	for time.Now().Before(deadline) {
		c := dialBounded(t, addr)
		code := getOn(t, c)
		_ = c.Close()
		if code == http.StatusOK {
			return
		}
	}
	t.Fatalf("no connection was served within %v of one closing: a closed connection did not free its slot", sessionBound)
}

// timedOut reports whether err is a read or write that ran out of time.
func timedOut(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func inflightRejections() uint64 {
	return telemetry.GetLimitStats().InflightRejected["max_connections"]
}

// TestAnHTTPEntrypointHoldsNoMoreThanMaxConnections: two idle keep-alive
// connections hold an entrypoint with max_connections 2 full -- a connection
// is what counts, not a request -- so the third is closed unanswered and
// counted with the other connection-limit rejections. One of the two closing
// frees its slot for the next.
func TestAnHTTPEntrypointHoldsNoMoreThanMaxConnections(t *testing.T) {
	addr := cappedHTTPEntrypoint(t, 2)
	first, second := keptAlive(t, addr), keptAlive(t, addr)

	before := inflightRejections()
	if !refusedHTTP(t, addr) {
		t.Fatal("a third connection to an HTTP entrypoint with max_connections 2 was served")
	}
	if got := inflightRejections() - before; got != 1 {
		t.Errorf("the refusal was counted %d times with the connection-limit rejections, want 1", got)
	}

	_ = first.Close()
	admittedHTTPWithin(t, addr)
	if code := getOn(t, second); code != http.StatusOK {
		t.Errorf("the connection that kept its slot got %d on its next request, want 200", code)
	}
}

// TestAFullHTTPEntrypointKeepsAccepting: the accept loop never waits for a
// slot. Every connection that arrives while the entrypoint is full is closed
// at once, one after another -- none is left queued in the kernel behind the
// connection holding the limit -- and the first to arrive once it is released
// is served.
func TestAFullHTTPEntrypointKeepsAccepting(t *testing.T) {
	addr := cappedHTTPEntrypoint(t, 1)
	holder := keptAlive(t, addr)
	for i := range 3 {
		if !refusedHTTP(t, addr) {
			t.Fatalf("connection %d past the limit was served while the only slot was held", i+1)
		}
	}
	_ = holder.Close()
	admittedHTTPWithin(t, addr)
}

// TestHTTP2StreamsAreNotLimitedByMaxConnections: an HTTP/2 connection is one
// connection however many streams it carries. Five requests in flight at once
// on one cleartext HTTP/2 connection all reach the handler on an entrypoint
// that holds a single connection; a limit counted in requests would have
// served one and left the other four waiting.
func TestHTTP2StreamsAreNotLimitedByMaxConnections(t *testing.T) {
	const streams = 5
	all := newBarrier(streams)
	var peersMu sync.Mutex
	peers := map[string]int{}
	deps := mockDepsForInspection(t)
	deps.BaseHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "not HTTP/2", http.StatusHTTPVersionNotSupported)
			return
		}
		if r.URL.Path == "/warm" {
			return
		}
		peersMu.Lock()
		peers[r.RemoteAddr]++
		peersMu.Unlock()
		if !all.arrive(r.Context()) {
			http.Error(w, "the other streams never arrived", http.StatusGatewayTimeout)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ep := &gateonv1.EntryPoint{Id: "h2c", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP, MaxConnections: 1}
	addr := httpEntrypointFor(t, ep, deps)

	// One connection first, so the burst below has one to share rather than
	// racing to dial its own.
	client := h2cClient(t)
	if code := statusOf(client, "http://"+addr+"/warm"); code != http.StatusOK {
		t.Fatalf("the first HTTP/2 request got %d, want 200", code)
	}
	before := inflightRejections()
	codes := make(chan int, streams)
	var wg sync.WaitGroup
	for range streams {
		wg.Go(func() { codes <- statusOf(client, "http://"+addr+"/") })
	}
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Errorf("one of %d concurrent streams on the entrypoint's one HTTP/2 connection got %d, want 200", streams, code)
		}
	}
	peersMu.Lock()
	defer peersMu.Unlock()
	if len(peers) != 1 || inflightRejections() != before {
		t.Errorf("the %d streams arrived on %d connections (%v), with %d refused; want all on one, none refused",
			streams, len(peers), peers, inflightRejections()-before)
	}
}

// TestHTTP3SharesTheEntrypointsConnectionLimit: on an HTTP/3 entrypoint a QUIC
// connection is a connection, and takes its slot from the same limit as the
// entrypoint's TCP connections -- the listener a client reaches it through is
// the client's choice, not a second allowance. One QUIC connection holds an
// entrypoint with max_connections 1 full: a TCP connection is refused, and so
// is a second QUIC connection, closed with H3_EXCESSIVE_LOAD. Its closing
// frees the slot.
func TestHTTP3SharesTheEntrypointsConnectionLimit(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	deps := mockDepsForInspection(t)
	deps.TLSConfig = serverTLS
	ep := &gateonv1.EntryPoint{Id: "capped-h3", Address: freeAddr(t), Type: gateonv1.EntryPoint_HTTP3,
		Tls: &gateonv1.TlsConfig{Enabled: true}, MaxConnections: 1}
	addr := httpEntrypointFor(t, ep, deps)

	h3 := clientTLS.Clone()
	h3.NextProtos = []string{http3.NextProtoH3}
	first := quicServedBy(t, addr, h3)
	if !refusedHTTP(t, addr) {
		t.Error("a TCP connection was admitted while a QUIC connection held the only slot")
	}
	if err := quicRefusal(t, addr, h3); err != nil {
		t.Error(err)
	}

	_ = first.CloseWithError(0, "")
	deadline := time.Now().Add(sessionBound)
	for {
		c := tls.Client(dialBounded(t, addr), clientTLS)
		code := getOn(t, c)
		_ = c.Close()
		if code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no TCP connection was served within %v of the QUIC connection closing", sessionBound)
		}
	}
}

// quicServedBy opens a QUIC connection to addr and returns it once the
// HTTP/3 server is serving it -- once it has opened its control stream, which
// it does as it takes the connection on.
func quicServedBy(t *testing.T, addr string, h3 *tls.Config) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), sessionBound)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, h3, &quic.Config{})
	if err != nil {
		t.Fatalf("QUIC dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.CloseWithError(0, "") })
	if _, err := c.AcceptUniStream(ctx); err != nil {
		t.Fatalf("the HTTP/3 server never took the first QUIC connection on: %v", err)
	}
	return c
}

// quicRefusal opens a QUIC connection to addr and returns nil once the server
// has closed it with H3_EXCESSIVE_LOAD, or an error saying what happened.
func quicRefusal(t *testing.T, addr string, h3 *tls.Config) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), sessionBound)
	defer cancel()
	c, err := quic.DialAddr(ctx, addr, h3, &quic.Config{})
	if err == nil {
		defer c.CloseWithError(0, "")
		select {
		case <-c.Context().Done():
			err = context.Cause(c.Context())
		case <-ctx.Done():
			return errors.New("a second QUIC connection was left open while the first held the only slot")
		}
	}
	if !closedByServerApplication(err) {
		return fmt.Errorf("a second QUIC connection ended with %w, want the server's H3_EXCESSIVE_LOAD", err)
	}
	return nil
}

// closedByServerApplication reports whether err is the server closing the
// connection with H3_EXCESSIVE_LOAD -- or, when it closed it before the
// handshake was done, with the transport's APPLICATION_ERROR, which is what
// RFC 9000 (10.2.3) has an application close become in handshake packets.
func closedByServerApplication(err error) bool {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.Remote && appErr.ErrorCode == quic.ApplicationErrorCode(http3.ErrCodeExcessiveLoad)
	}
	var transportErr *quic.TransportError
	return errors.As(err, &transportErr) && transportErr.Remote &&
		transportErr.ErrorCode == quic.ApplicationErrorErrorCode
}

// TestManagementStaysReachableWhileAnEntrypointIsFull: the management
// listener takes no slot from any entrypoint's limit and has none of its own,
// so a data-plane entrypoint that a flood holds full leaves it reachable.
// ADR 0032 says why it is not capped.
func TestManagementStaysReachableWhileAnEntrypointIsFull(t *testing.T) {
	for _, env := range []string{"GATEON_MANAGEMENT_BIND", "GATEON_MANAGEMENT_PORT",
		"GATEON_MANAGEMENT_ALLOWED_IPS", "GATEON_MANAGEMENT_HOST"} {
		t.Setenv(env, "")
	}
	data := cappedHTTPEntrypoint(t, 1)
	_ = keptAlive(t, data)
	if !refusedHTTP(t, data) {
		t.Fatal("setup: the data-plane entrypoint is not full; the rest proves nothing")
	}

	deps := mockDepsForInspection(t)
	capture := &addrCapture{addrs: make(chan net.Addr, 1)}
	deps.Phantom = capture
	deps.ManagementConfig = &gateonv1.ManagementConfig{Bind: "127.0.0.1", Port: "0"}
	wg := &syncutil.WaitGroup{}
	startSecureManagementServer("0", deps, wg)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), sessionBound)
		defer cancel()
		deps.ShutdownRegistry.ShutdownAll(ctx)
		wg.Wait()
	})
	mgmt := (<-capture.addrs).String()
	for i := range 3 {
		c := dialBounded(t, mgmt)
		if code := getOn(t, c); code != http.StatusOK {
			t.Fatalf("management request %d got %d while a data-plane entrypoint was full, want 200", i+1, code)
		}
	}
}

// barrier releases the requests waiting on it once n have arrived.
type barrier struct {
	mu      sync.Mutex
	waiting int
	n       int
	open    chan struct{}
}

func newBarrier(n int) *barrier { return &barrier{n: n, open: make(chan struct{})} }

// arrive waits until n requests have arrived, and reports false if ctx ends
// or sessionBound passes first.
func (b *barrier) arrive(ctx context.Context) bool {
	b.mu.Lock()
	b.waiting++
	if b.waiting == b.n {
		close(b.open)
	}
	b.mu.Unlock()
	select {
	case <-b.open:
		return true
	case <-ctx.Done():
		return false
	case <-time.After(sessionBound):
		return false
	}
}

// h2cClient speaks cleartext HTTP/2 with prior knowledge, over one connection
// per host for as long as that connection has streams to spare.
func h2cClient(t *testing.T) *http.Client {
	t.Helper()
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: p}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: sessionBound}
}

// statusOf is the status of a GET to url, or 0 when it failed.
func statusOf(c *http.Client, url string) int {
	resp, err := c.Get(url)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestATLSEntrypointHoldsNoMoreThanMaxConnections: the limit is taken when a
// connection is accepted, before its TLS handshake, so the connection past it
// costs the gateway no handshake -- its client's fails -- and a connection
// that closes frees its slot as a plaintext one does.
func TestATLSEntrypointHoldsNoMoreThanMaxConnections(t *testing.T) {
	serverTLS, clientTLS := selfSignedTLS(t)
	deps := mockDepsForInspection(t)
	deps.TLSConfig = serverTLS
	ep := &gateonv1.EntryPoint{Id: "capped-https", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP,
		Tls: &gateonv1.TlsConfig{Enabled: true}, MaxConnections: 2}
	addr := httpEntrypointFor(t, ep, deps)

	first, second := keptAliveTLS(t, addr, clientTLS), keptAliveTLS(t, addr, clientTLS)
	third := tls.Client(dialBounded(t, addr), clientTLS)
	switch err := third.Handshake(); {
	case err == nil:
		t.Fatal("a third TLS connection to an entrypoint with max_connections 2 completed its handshake")
	case timedOut(err):
		t.Fatalf("a third TLS connection was neither served nor closed within %v: it waited for a slot", sessionBound)
	}
	_ = first.Close()
	deadline := time.Now().Add(sessionBound)
	for {
		c := tls.Client(dialBounded(t, addr), clientTLS)
		err := c.Handshake()
		_ = c.Close()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no TLS connection was admitted within %v of one closing", sessionBound)
		}
	}
	_ = second.Close()
}

// keptAliveTLS completes one request on a TLS connection to addr and returns
// it open.
func keptAliveTLS(t *testing.T, addr string, clientTLS *tls.Config) net.Conn {
	t.Helper()
	c := tls.Client(dialBounded(t, addr), clientTLS)
	if code := getOn(t, c); code != http.StatusOK {
		t.Fatalf("a request on a TLS connection the entrypoint admitted got %d, want 200", code)
	}
	return c
}

// TestConnSlotsHoldNoMoreThanTheirLimit pins the accounting the listeners rest
// on: a slot is taken until its connection closes, however many times it is
// closed, and never past the limit.
func TestConnSlotsHoldNoMoreThanTheirLimit(t *testing.T) {
	slots := newConnSlots(&gateonv1.EntryPoint{Id: "slots", MaxConnections: 2})
	a, b := &slotConn{Conn: pipeEnd(t), slots: slots}, &slotConn{Conn: pipeEnd(t), slots: slots}
	if first, second := slots.take(), slots.take(); !first || !second {
		t.Fatal("two slots could not be taken under a limit of 2")
	}
	if slots.take() {
		t.Fatal("a third slot was taken under a limit of 2")
	}
	_ = a.Close()
	_ = a.Close() // net/http closes a connection more than once
	if got := slots.held.Load(); got != 1 {
		t.Fatalf("closing one connection twice left %d slots held, want 1", got)
	}
	if !slots.take() {
		t.Fatal("the slot a closed connection freed could not be taken")
	}
	_ = b.Close()
}

// TestAnHTTPEntrypointWithoutMaxConnectionsTakesTheProfileDefault: 0 is the
// resource profile's limit, not no limit.
func TestAnHTTPEntrypointWithoutMaxConnectionsTakesTheProfileDefault(t *testing.T) {
	for profile, want := range map[string]int64{"minimal": 1000, "standard": 10000, "enterprise": 50000} {
		t.Setenv("GATEON_PROFILE", profile)
		if got := newConnSlots(&gateonv1.EntryPoint{Id: "default"}).limit; got != want {
			t.Errorf("on the %s profile an HTTP entrypoint with max_connections 0 holds %d, want %d", profile, got, want)
		}
	}
}
