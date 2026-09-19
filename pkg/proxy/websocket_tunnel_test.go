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
