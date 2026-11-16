// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/security/wsinspect"
)

// The WAF inspects WebSocket messages by replacing the connection this
// package takes with Hijack (wsinspect.Guard). These tests put that guard in
// front of the real upgrade path, because the guard only works if the tunnel
// reads the client through the connection it was handed: a tunnel that kept
// the socket net/http gave it, or the reader that came with it, would relay
// every message around the inspection.

// maskedText is one masked client text frame.
func maskedText(payload string) []byte {
	key := [4]byte{7, 11, 13, 17}
	out := []byte{0x81, 0x80 | byte(len(payload))}
	out = append(out, key[:]...)
	for i := range len(payload) {
		out = append(out, payload[i]^key[i&3])
	}
	return out
}

// recordingBackend answers 101 and reports every byte the tunnel then gives it.
func recordingBackend(t *testing.T) (*httptest.Server, <-chan []byte) {
	t.Helper()
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("backend hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		b, _ := io.ReadAll(rw.Reader)
		got <- b
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

// guardedGateway serves a ProxyHandler behind a guard that refuses any
// message containing "attack".
func guardedGateway(t *testing.T, backendURL string) *httptest.Server {
	t.Helper()
	h := &ProxyHandler{
		lb:              NewRoundRobinLB([]string{backendURL}),
		stopDiscovery:   make(chan struct{}),
		stopHealthCheck: make(chan struct{}),
	}
	opts := wsinspect.Options{Inspect: func(p []byte, _ bool) wsinspect.Verdict {
		if strings.Contains(string(p), "attack") {
			return wsinspect.Refuse
		}
		return wsinspect.Allow
	}}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(wsinspect.Guard(w, opts), r)
	}))
	t.Cleanup(gw.Close)
	return gw
}

func TestAGuardedTunnelRelaysOnlyMessagesTheGuardAllowed(t *testing.T) {
	backend, got := recordingBackend(t)
	gw := guardedGateway(t, backend.URL)
	conn, br := dialUpgrade(t, gw.URL, nil)

	clean := maskedText("hello")
	// Sent in one write with the attack behind it, and split mid-frame, so
	// neither message boundaries nor write boundaries line up with reads.
	wire := append(append(bytes.Clone(clean), maskedText("an attack")...), maskedText("after")...)
	_, _ = conn.Write(wire[:3])
	_, _ = conn.Write(wire[3:])

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	closeFrame, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("the client was not hung up on after the refused message: %v", err)
	}
	if want := []byte{0x88, 2, 0x03, 0xF0}; !bytes.Equal(closeFrame, want) {
		t.Errorf("the client got %x, want a close frame with code 1008 (%x)", closeFrame, want)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, clean) {
			t.Errorf("the backend received %q, want only the first message %q", b, clean)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the backend's side of the tunnel was not closed after the refusal")
	}
}

// The half-close the tunnel gives a client when the backend hangs up has to
// survive the guard: the tunnel finds CloseWrite on the connection by type,
// and a wrapper without it would leave the client waiting again.
func TestAGuardedTunnelStillTellsTheClientWhenTheBackendCloses(t *testing.T) {
	backend, _ := upgradeBackend(t)
	gw := guardedGateway(t, backend.URL)
	conn, br := dialUpgrade(t, gw.URL, nil)

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("client read after the backend closed: got %v, want io.EOF", err)
	}
}
