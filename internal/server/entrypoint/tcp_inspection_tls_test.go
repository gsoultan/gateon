// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/syncutil"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// protocolRecordingResolver reports the protocol each TCP resolution asked
// for, which is the only observable difference between the inspected and the
// uninspected path.
type protocolRecordingResolver struct {
	protocols chan string
}

func (r *protocolRecordingResolver) ResolveTCP(_ *gateonv1.EntryPoint, protocol string) l4.TCPProxy {
	r.protocols <- protocol
	return hangupProxy{}
}

func (r *protocolRecordingResolver) ResolveUDP(*gateonv1.EntryPoint) l4.UDPProxy { return nil }

type hangupProxy struct{}

func (hangupProxy) ProxyTCP(_ context.Context, c net.Conn) { _ = c.Close() }

// freeAddr reserves a loopback port and releases it for startTCPServer, which
// does its own Listen and offers no way to learn the address it bound.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestTCPEntrypointInspectsPlaintextEvenWhenGatewayHasTLS is the regression
// guard for a plaintext TCP entrypoint losing protocol detection. Whether a
// connection was inspected was decided by whether the *gateway* had a TLS
// config at all, not by whether this listener was a TLS listener. The moment
// any HTTPS entrypoint existed -- the ordinary shape, 443 next to 22 -- every
// plaintext TCP entrypoint stopped detecting SSH, RDP and HTTP, and a route
// typed "ssh" could no longer be reached.
func TestTCPEntrypointInspectsPlaintextEvenWhenGatewayHasTLS(t *testing.T) {
	resolver := &protocolRecordingResolver{protocols: make(chan string, 4)}
	deps := mockDepsForInspection(t)
	deps.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12} // some other entrypoint terminates TLS
	deps.L4Resolver = resolver

	addr := freeAddr(t)
	ep := &gateonv1.EntryPoint{
		Id:        "ssh-ep",
		Address:   addr,
		Type:      gateonv1.EntryPoint_TCP,
		Protocols: []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
		// No Tls block: this listener is plaintext.
	}
	wg := &syncutil.WaitGroup{}
	reg := &ShutdownRegistry{}
	startTCPServer(addr, ep, deps, wg, reg)
	t.Cleanup(func() {
		reg.ShutdownAll(context.Background())
		wg.Wait()
	})

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial entrypoint: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n")); err != nil {
		t.Fatalf("write ssh banner: %v", err)
	}

	select {
	case got := <-resolver.protocols:
		if got != "ssh" {
			t.Fatalf("resolver asked for protocol %q, want \"ssh\": the plaintext entrypoint skipped inspection because the gateway has a TLS config", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resolver was never consulted")
	}
}
