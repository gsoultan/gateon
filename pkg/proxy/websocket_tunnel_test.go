// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// upgradeBackend accepts any Upgrade request: it reports the headers it was
// sent, hijacks the connection, answers 101, and then hangs up straight away.
// Hanging up first is the point -- it is the side of the tunnel the proxy has
// to relay to the client.
func upgradeBackend(t *testing.T) (*httptest.Server, <-chan http.Header) {
	t.Helper()
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("backend response writer does not support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

// upgradeGateway serves a ProxyHandler for one backend without starting the
// health checker or discovery, which the test does not need.
func upgradeGateway(t *testing.T, backendURL string) *httptest.Server {
	t.Helper()
	h := &ProxyHandler{
		lb:              NewRoundRobinLB([]string{backendURL}),
		stopDiscovery:   make(chan struct{}),
		stopHealthCheck: make(chan struct{}),
	}
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	return gw
}

// dialUpgrade sends a raw Upgrade request to the gateway and returns once the
// 101 has been read, leaving the connection positioned at the tunnel bytes.
func dialUpgrade(t *testing.T, gwURL string, extra http.Header) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, err := url.Parse(gwURL)
	if err != nil {
		t.Fatalf("parse gateway url: %v", err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req := "GET /ws HTTP/1.1\r\nHost: " + u.Host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
	for k, vs := range extra {
		for _, v := range vs {
			req += k + ": " + v + "\r\n"
		}
	}
	req += "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	// A 101 has no body and the connection is deliberately kept for the
	// tunnel, so this closes the Body only, not conn.
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
	}
	return conn, br
}

// TestProxyUpgradeTellsClientWhenBackendCloses is the regression guard for a
// one-sided teardown. When the backend hung up, the proxy stopped copying to the
// client but never half-closed the client's side, so the client was never told
// and the handler sat on the client->backend copy until the client gave up on
// its own -- one goroutine and two connections per backend-initiated close,
// held for as long as the client cared to wait.
func TestProxyUpgradeTellsClientWhenBackendCloses(t *testing.T) {
	backend, _ := upgradeBackend(t)
	gw := upgradeGateway(t, backend.URL)

	conn, br := dialUpgrade(t, gw.URL, nil)

	// The backend has already closed. Without the client closing anything, its
	// next read must see EOF; the deadline is only a bound on the hang.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := br.ReadByte()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("client read after the backend closed: got %v, want io.EOF (the tunnel never half-closed the client side)", err)
	}
}

// TestClientReaderReplaysBytesAlreadyBuffered covers the helper the upgrade
// path reads the client side of the tunnel through. The hijack now happens
// after the backend has answered, and net/http's background read is live on
// the connection until then, so bytes can be sitting in the hijacked
// bufio.Reader rather than on the socket. Reading the bare connection would
// silently drop them; the tunnel has to see them first.
func TestClientReaderReplaysBytesAlreadyBuffered(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	writes := make(chan error, 1)
	go func() {
		defer client.Close()
		if _, err := client.Write([]byte("AB")); err != nil {
			writes <- err
			return
		}
		_, err := client.Write([]byte("CD"))
		writes <- err
	}()

	buffered := bufio.NewReader(server)
	if _, err := buffered.Peek(2); err != nil {
		t.Fatalf("buffer the first write: %v", err)
	}
	got, err := io.ReadAll(clientReader(server, buffered))
	if err != nil {
		t.Fatalf("read tunnel source: %v", err)
	}
	if werr := <-writes; werr != nil {
		t.Fatalf("client write: %v", werr)
	}
	if string(got) != "ABCD" {
		t.Fatalf("tunnel source read %q, want %q: bytes buffered before the hijack were lost", got, "ABCD")
	}
}

// rawUpgradeBackend accepts connections and hands each, once its request has
// been read, to serve; the test ends when every one has returned.
func rawUpgradeBackend(t *testing.T, serve func(net.Conn, *bufio.Reader)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				serve(c, br)
			})
		}
	})
	return "http://" + ln.Addr().String()
}

// switched answers 101 on c.
func switched(c net.Conn) bool {
	_, err := io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	return err == nil
}

// TestAnUpgradeBackendThatNeverAnswersIsCutByTheResponseHeaderTimeout: the
// backend's answer to an upgrade is bounded like any other response's. It was
// read with no deadline, so a backend that never answered held the request,
// a goroutine and a backend connection for as long as the client stayed --
// here there are no entrypoint deadlines in front to end it either.
func TestAnUpgradeBackendThatNeverAnswersIsCutByTheResponseHeaderTimeout(t *testing.T) {
	backend := rawUpgradeBackend(t, func(c net.Conn, br *bufio.Reader) { _, _ = io.Copy(io.Discard, br) })
	h := &ProxyHandler{
		lb:                   NewRoundRobinLB([]string{backend}),
		stopDiscovery:        make(chan struct{}),
		stopHealthCheck:      make(chan struct{}),
		upgradeHeaderTimeout: 300 * time.Millisecond,
	}
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)
	u, _ := url.Parse(gw.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: "+u.Host+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer 5s after an upgrade whose backend never answered (300ms response-header timeout): %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("an upgrade whose backend never answered was answered %d, want 502", resp.StatusCode)
	}
}

// TestATunnelStaysOpenWhileOneSideTalksAndEndsWhenNeitherDoes: a byte in
// either direction keeps the whole tunnel open -- a backend pushing to a
// client that never writes is not idle -- and nothing in either direction for
// the idle timeout ends it.
func TestATunnelStaysOpenWhileOneSideTalksAndEndsWhenNeitherDoes(t *testing.T) {
	const idle = 400 * time.Millisecond
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", idle.String())
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", "1m")
	const pushes = 10 // 10 x 100ms is two and a half idle timeouts
	backend := rawUpgradeBackend(t, func(c net.Conn, br *bufio.Reader) {
		if !switched(c) {
			return
		}
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for range pushes {
			<-tick.C
			if _, err := c.Write([]byte("p")); err != nil {
				return
			}
		}
		_, _ = io.Copy(io.Discard, br) // silent now, until the gateway closes
	})
	conn, br := dialUpgrade(t, upgradeGateway(t, backend).URL, nil)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := range pushes {
		if _, err := br.ReadByte(); err != nil {
			t.Fatalf("push %d of %d never arrived (%v): a client that only listens was treated as idle", i+1, pushes, err)
		}
	}
	last := time.Now()
	_, err := br.ReadByte()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read after both sides went quiet: %v, want EOF from the %v idle timeout", err, idle)
	}
	if quiet := time.Since(last); quiet < idle/2 {
		t.Fatalf("the tunnel closed %v after its last byte, inside the %v idle timeout", quiet, idle)
	}
}

// TestATunnelEndsAtItsMaxLifetime: a tunnel that never goes quiet still ends
// at its maximum lifetime.
func TestATunnelEndsAtItsMaxLifetime(t *testing.T) {
	const lifetime = 600 * time.Millisecond
	t.Setenv("GATEON_STREAM_IDLE_TIMEOUT", "5s")
	t.Setenv("GATEON_STREAM_MAX_LIFETIME", lifetime.String())
	backend := rawUpgradeBackend(t, func(c net.Conn, br *bufio.Reader) {
		if switched(c) {
			_, _ = io.Copy(c, br)
		}
	})
	conn, br := dialUpgrade(t, upgradeGateway(t, backend).URL, nil)
	start := time.Now()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for {
		<-tick.C
		if _, err := conn.Write([]byte("e")); err != nil {
			break
		}
		if _, err := br.ReadByte(); err != nil {
			// EOF, or a reset when the gateway closed with a byte of ours
			// still unread: ended either way. Only the test's own deadline is
			// not an end.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("a busy tunnel was still open 5s on: no maximum lifetime (%v)", err)
			}
			break
		}
	}
	if took := time.Since(start); took < lifetime*3/4 || took > 5*time.Second {
		t.Fatalf("a busy tunnel ended after %v, want about its %v lifetime", took, lifetime)
	}
}

// TestProxyUpgradeOverwritesClientSuppliedIdentityHeaders checks that the
// upgrade path normalises the same forwarding headers the HTTP path does. It
// copied every inbound header into the backend request and only set
// X-Forwarded-For and X-Forwarded-Proto, so a WebSocket client could hand the
// backend its own X-Real-IP, X-Forwarded-Host and Forwarded -- the headers a
// backend reads for the client's identity and its own public hostname.
func TestProxyUpgradeOverwritesClientSuppliedIdentityHeaders(t *testing.T) {
	backend, seen := upgradeBackend(t)
	gw := upgradeGateway(t, backend.URL)

	hostile := http.Header{}
	hostile.Set("X-Real-IP", "203.0.113.9")
	hostile.Set("X-Forwarded-Host", "victim.example")
	hostile.Set("Forwarded", "for=203.0.113.9;host=victim.example")
	dialUpgrade(t, gw.URL, hostile)

	var got http.Header
	select {
	case got = <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received the upgrade request")
	}

	gwHost, err := url.Parse(gw.URL)
	if err != nil {
		t.Fatalf("parse gateway url: %v", err)
	}
	if v := got.Get("X-Real-IP"); v != "127.0.0.1" {
		t.Errorf("X-Real-IP reached the backend as %q, want the connecting client 127.0.0.1", v)
	}
	if v := got.Get("X-Forwarded-Host"); v != gwHost.Host {
		t.Errorf("X-Forwarded-Host reached the backend as %q, want the requested host %q", v, gwHost.Host)
	}
	if v := got.Get("Forwarded"); v != "" {
		t.Errorf("client-supplied Forwarded header reached the backend: %q", v)
	}
}
