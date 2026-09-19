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
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// echoBackendProxy is a TCPProxy that echoes with a prefix, so the test can
// tell the client's own bytes apart from what came back through the gateway.
type echoBackendProxy struct{}

func (echoBackendProxy) ProxyTCP(_ context.Context, c net.Conn) {
	defer c.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(c, "TCP Echo: %s", line)
}

type echoResolver struct{}

func (echoResolver) ResolveTCP(*gateonv1.EntryPoint, string) l4.TCPProxy { return echoBackendProxy{} }
func (echoResolver) ResolveUDP(*gateonv1.EntryPoint) l4.UDPProxy         { return nil }

// TestTCPEntrypointProxiesTheFirstBytesAfterInspecting is the half the
// inspection change was missing.
//
// Turning inspection on for a plaintext entrypoint is only correct if what the
// inspector read on the client's behalf still reaches the backend. The
// inspector consumes the first read into a peek buffer to identify the
// protocol; an ordinary client that speaks first -- which is most of them, and
// is what the end-to-end TCP check does -- has its opening line in that buffer.
// If it is not replayed, the backend waits for a line that already arrived and
// the session dies with nothing sent.
//
// The sibling test asserts that inspection happens. This one asserts the bytes
// survive it.
func TestTCPEntrypointProxiesTheFirstBytesAfterInspecting(t *testing.T) {
	deps := mockDepsForInspection(t)
	deps.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12} // another entrypoint terminates TLS
	deps.L4Resolver = echoResolver{}

	addr := freeAddr(t)
	ep := &gateonv1.EntryPoint{
		Id:        "tcp-ep",
		Address:   addr,
		Type:      gateonv1.EntryPoint_TCP,
		Protocols: []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
	}
	wg := &syncutil.WaitGroup{}
	reg := &ShutdownRegistry{}
	startTCPServer(addr, ep, deps, wg, reg)
	t.Cleanup(func() {
		reg.ShutdownAll(context.Background())
		wg.Wait()
	})

	conn := dialWhenReady(t, addr)
	defer conn.Close()

	const sent = "Gateon TCP Test: This is exactly 24 bytes plus newline\n"
	if _, err := io.WriteString(conn, sent); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("the client sent its opening line and got nothing back (%v). "+
			"The inspector reads that line into its peek buffer to identify the "+
			"protocol; if it is not replayed, the backend never sees it.", err)
	}
	if want := "TCP Echo: " + sent; got != want {
		t.Errorf("round trip = %q, want %q", got, want)
	}
}

// dialWhenReady retries until the entrypoint's listener is accepting, since
// startTCPServer binds on a goroutine and offers no readiness signal.
func dialWhenReady(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("entrypoint never accepted a connection on %s: %v", addr, err)
		}
	}
}
