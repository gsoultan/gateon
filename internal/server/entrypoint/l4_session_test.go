// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/phantom"
	"github.com/gsoultan/gateon/internal/syncutil"
	gtls "github.com/gsoultan/gateon/internal/tls"
	"github.com/gsoultan/gateon/pkg/l4"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serveBackend runs handle for every connection to a loopback listener until
// stop, which waits for the handlers.
func serveBackend(tb testing.TB, handle func(net.Conn)) (addr string, stop func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	var handlers sync.WaitGroup
	served := make(chan struct{})
	go func() {
		defer close(served)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			handlers.Go(func() {
				defer c.Close()
				handle(c)
			})
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-served
		handlers.Wait()
	}
}

// l4Resolver builds the resolver cmd/gateon builds, over registries holding
// one generic TCP route from entrypoint epID to backend.
func l4Resolver(tb testing.TB, epID, backend string) L4Resolver {
	tb.Helper()
	dir := tb.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	svc := &gateonv1.Service{
		Id:              "l4-svc",
		Name:            "l4-svc",
		BackendType:     "tcp",
		WeightedTargets: []*gateonv1.Target{{Url: "tcp://" + backend, Weight: 1}},
	}
	if err := services.Update(context.Background(), svc); err != nil {
		tb.Fatalf("add service: %v", err)
	}
	rt := &gateonv1.Route{Id: "l4-route", Type: "tcp", Entrypoints: []string{epID}, ServiceId: svc.Id}
	if err := routes.Update(context.Background(), rt); err != nil {
		tb.Fatalf("add route: %v", err)
	}
	return WrapL4Resolver(l4.NewResolver(routes, services))
}

// plaintextTCPEntrypoint starts a plaintext TCP entrypoint, wired the way
// cmd/gateon wires one, whose one route leads to backend.
func plaintextTCPEntrypoint(tb testing.TB, backend string) (addr string, stop func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("reserve port: %v", err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()

	ep := &gateonv1.EntryPoint{
		Id:        "l4-tcp",
		Address:   addr,
		Type:      gateonv1.EntryPoint_TCP,
		Protocols: []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
	}
	reg := &ShutdownRegistry{}
	deps := &Deps{
		TLSManager:       gtls.NewManager(gtls.Config{}),
		Limiter:          traffic.NoopRateLimiter{},
		ShutdownRegistry: reg,
		L4Resolver:       l4Resolver(tb, ep.Id, backend),
		GlobalStore:      config.NewGlobalRegistry(filepath.Join(tb.TempDir(), "global.json")),
		Phantom:          phantom.NewPhantomCore(),
	}
	wg := &syncutil.WaitGroup{}
	startTCPServer(addr, ep, deps, wg, reg) // binds before it returns
	return addr, func() {
		reg.ShutdownAll(context.Background())
		wg.Wait()
	}
}

// TestAPlaintextL4SessionEndsWhenTheBackendHangsUp: a backend that answers and
// closes -- whois, finger, a server that ends its response by closing --
// must end the client's session through a plaintext TCP entrypoint.
//
// The entrypoint reads a connection's first bytes to identify its protocol and
// hands the L4 proxy a wrapper that replays them. The proxy half-closes the
// client when the backend is done by asserting CloseWrite on what it was
// handed, which the wrapper did not have, so the client never read EOF and
// the session stayed open until the client gave up.
func TestAPlaintextL4SessionEndsWhenTheBackendHangsUp(t *testing.T) {
	backend, stopBackend := serveBackend(t, func(c net.Conn) {
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return
		}
		_, _ = io.WriteString(c, "answer to "+line) // then hang up
	})
	defer stopBackend()
	addr, stop := plaintextTCPEntrypoint(t, backend)
	defer stop()

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "whois example\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("the backend answered %q and hung up, but the client was never told: %v", got, err)
	}
	if want := "answer to whois example\n"; string(got) != want {
		t.Errorf("client read %q, want %q -- the inspected first bytes must reach the backend first", got, want)
	}
}

// TestPeekedConnHandsOverItsUnreadBytesOnce pins the ReadAhead contract the L4
// proxy relies on: the bytes not yet read, the connection underneath, and no
// replay afterwards -- a byte sent twice would corrupt the stream.
func TestPeekedConnHandsOverItsUnreadBytesOnce(t *testing.T) {
	inner, peer := net.Pipe()
	defer inner.Close()
	defer peer.Close()
	pc := newPeekedConn(inner, []byte("SSH-2.0-"))

	first := make([]byte, 4)
	if n, err := pc.Read(first); err != nil || string(first[:n]) != "SSH-" {
		t.Fatalf("first read = %q, %v; want the start of the peeked bytes", first[:n], err)
	}
	pending, conn := pc.ReadAhead()
	if string(pending) != "2.0-" {
		t.Errorf("ReadAhead pending = %q, want the peeked bytes not yet read, %q", pending, "2.0-")
	}
	if conn != inner {
		t.Errorf("ReadAhead returned %T, want the connection the wrapper reads from", conn)
	}
	if again, _ := pc.ReadAhead(); len(again) != 0 {
		t.Errorf("a second ReadAhead returned %q again", again)
	}

	go func() { _, _ = peer.Write([]byte("OpenSSH")) }()
	next := make([]byte, 7)
	if _, err := io.ReadFull(pc, next); err != nil || string(next) != "OpenSSH" {
		t.Errorf("read after ReadAhead = %q, %v; want the connection's own bytes, not a replay", next, err)
	}
}
