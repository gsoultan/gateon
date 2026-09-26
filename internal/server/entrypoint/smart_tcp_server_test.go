// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// A TCP entrypoint that finds HTTP on a connection serves it from a shared
// http.Server, which set the entrypoint's read and write timeouts on the
// server itself. A server write timeout bounds the whole response, and it
// stays on a hijacked connection, so a Server-Sent Events stream or a
// WebSocket through a TCP entrypoint was cut when it ran out -- fifteen
// seconds by default. The HTTP entrypoint sets its deadlines per request and
// skips them for streams and upgrades; this server now does the same.
func TestAStreamThroughATCPEntrypointOutlivesTheWriteTimeout(t *testing.T) {
	deps := mockDepsForInspection(t)
	const events = 8
	deps.BaseHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range events {
			_, _ = fmt.Fprintf(w, "data: %d\n\n", i)
			http.NewResponseController(w).Flush()
			time.Sleep(60 * time.Millisecond)
		}
	})
	ep := &gateonv1.EntryPoint{Id: "tcp-sse", Name: "tcp-sse", Type: gateonv1.EntryPoint_TCP, WriteTimeoutMs: 150}
	addr := serveAsSharedHTTP(t, ep, deps)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	got := 0
	for sc := bufio.NewScanner(resp.Body); sc.Scan(); {
		if strings.HasPrefix(sc.Text(), "data: ") {
			got++
		}
	}
	if got != events {
		t.Fatalf("an event stream through a TCP entrypoint delivered %d of %d events; the 150ms write "+
			"timeout cut it", got, events)
	}
}

// The plain-HTTP handler behind a TCP entrypoint has a branch for gRPC over
// HTTP/2, and the sniffer hands it connections that open with the HTTP/2
// preface -- but the server it runs in did not speak cleartext HTTP/2, so a
// prior-knowledge h2c client, which is how gRPC runs without TLS, was refused.
func TestATCPEntrypointServesCleartextHTTP2(t *testing.T) {
	deps := mockDepsForInspection(t)
	deps.BaseHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})
	ep := &gateonv1.EntryPoint{Id: "tcp-h2c", Name: "tcp-h2c", Type: gateonv1.EntryPoint_TCP}
	addr := serveAsSharedHTTP(t, ep, deps)

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	resp, err := client.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("a prior-knowledge HTTP/2 request to a TCP entrypoint failed: %v", err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); string(body) != "HTTP/2.0" {
		t.Fatalf("the request was served as %q", body)
	}
}

// serveAsSharedHTTP accepts on a loopback listener and hands every connection
// to serveConnAsHTTP, as a TCP entrypoint does once it has sniffed HTTP.
func serveAsSharedHTTP(t *testing.T, ep *gateonv1.EntryPoint, deps *Deps) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		deps.ShutdownRegistry.ShutdownAll(ctx)
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			serveConnAsHTTP(conn, nil, ep, deps)
		}
	}()
	return ln.Addr().String()
}
