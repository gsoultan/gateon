// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// HTTP/2 over TLS used to reach the handler through x/net's server, installed
// by http2.ConfigureServer with the stream and frame caps. x/net 0.60.0
// deprecates that, and the server now relies on net/http's own HTTP/2. These
// prove the move kept both halves: a TLS entrypoint still negotiates h2, and
// it still tells every client the Rapid-Reset stream cap rather than Go's
// default.
func TestATLSEntrypointServesHTTP2UnderItsStreamCap(t *testing.T) {
	addr, clientTLS := tlsEntrypointServer(t)

	clientTLS.NextProtos = []string{"h2"}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS, ForceAttemptHTTP2: true}}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET over TLS: %v", err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); string(body) != "HTTP/2.0" {
		t.Fatalf("a TLS entrypoint served %q, want HTTP/2.0", body)
	}

	if got := advertisedMaxConcurrentStreams(t, addr, clientTLS); got != h2MaxConcurrentStreams {
		t.Fatalf("SETTINGS_MAX_CONCURRENT_STREAMS = %d, want %d", got, h2MaxConcurrentStreams)
	}
}

// The cap on the wire happens to equal Go's default, so the frame alone cannot
// tell a cap the gateway set from one it inherited. The server's own config
// can: both caps are set explicitly, as the net profile requires.
func TestTheEntrypointServerSetsItsHTTP2CapsExplicitly(t *testing.T) {
	e := &httpEntrypoint{ep: &gateonv1.EntryPoint{Id: "h2-caps", Address: "127.0.0.1:0"}}
	cfg := e.newServer(http.NotFoundHandler()).HTTP2
	if cfg == nil || cfg.MaxConcurrentStreams != h2MaxConcurrentStreams || cfg.MaxReadFrameSize != h2MaxReadFrameSize {
		t.Fatalf("HTTP/2 config = %+v, want MaxConcurrentStreams %d and MaxReadFrameSize %d",
			cfg, h2MaxConcurrentStreams, h2MaxReadFrameSize)
	}
}

// tlsEntrypointServer serves an HTTP entrypoint's server over TLS on a
// loopback port, with a handler that answers the request's protocol, and
// returns its address and a client config that trusts it.
func tlsEntrypointServer(t *testing.T) (string, *tls.Config) {
	t.Helper()
	serverTLS, clientTLS := selfSignedTLS(t)
	e := &httpEntrypoint{
		ep:        &gateonv1.EntryPoint{Id: "h2-tls", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP},
		tlsConfig: serverTLS,
	}
	server := e.newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.ServeTLS(l, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return l.Addr().String(), clientTLS
}

// advertisedMaxConcurrentStreams opens an h2 connection by hand and returns
// the SETTINGS_MAX_CONCURRENT_STREAMS the server's first SETTINGS frame names.
func advertisedMaxConcurrentStreams(t *testing.T, addr string, clientTLS *tls.Config) uint32 {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("negotiated %q, want h2", p)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("settings: %v", err)
	}
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatalf("reading the server's first frame: %v", err)
	}
	sf, ok := f.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("the server's first frame is %T, want SETTINGS", f)
	}
	v, ok := sf.Value(http2.SettingMaxConcurrentStreams)
	if !ok {
		t.Fatal("the server's SETTINGS frame names no MAX_CONCURRENT_STREAMS")
	}
	return v
}
