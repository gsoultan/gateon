// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package entrypoint

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/syncutil"
	gtls "github.com/gsoultan/gateon/internal/tls"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// BenchmarkTCPEntrypointHTTPSession is one plaintext HTTP request per
// operation, each on its own connection, through a TCP entrypoint: accept,
// protocol detection, the entrypoint's HTTP server and chain, close. It is the
// client-first path that handing silent clients to the TCP route must leave
// as it was. It uses only fixtures older than that change, so it runs against
// the tree before it as well.
func BenchmarkTCPEntrypointHTTPSession(b *testing.B) {
	addr, stop := httpOverTCPEntrypoint(b)
	defer stop()
	req := []byte("GET / HTTP/1.1\r\nHost: gw.example.test\r\nConnection: close\r\n\r\n")

	b.ReportAllocs()
	start := benchCPU(b)
	for b.Loop() {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		if _, err := c.Write(req); err != nil {
			b.Fatalf("write: %v", err)
		}
		if resp, err := io.ReadAll(c); err != nil || len(resp) == 0 {
			b.Fatalf("response %q: %v", resp, err)
		}
		_ = c.Close()
	}
	reportBenchCPU(b, start)
}

// httpOverTCPEntrypoint starts a plaintext TCP entrypoint whose HTTP server
// answers every request with "ok", with the resolver the other fixtures use
// -- an HTTP route and a tcp route on it -- so that each connection pays for
// deciding whether the entrypoint has anything to inspect. The tcp route's
// backend is never dialled: every request here speaks first.
func httpOverTCPEntrypoint(b *testing.B) (addr string, stop func()) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("reserve port: %v", err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()
	ep := &gateonv1.EntryPoint{
		Id:        "http-over-tcp",
		Address:   addr,
		Type:      gateonv1.EntryPoint_TCP,
		Protocols: []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
	}
	reg := &ShutdownRegistry{}
	deps := &Deps{
		BaseHandler:      http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		Wrapped:          &mockGRPCWeb{},
		TLSManager:       gtls.NewManager(gtls.Config{}),
		Limiter:          traffic.NoopRateLimiter{},
		ShutdownRegistry: reg,
		L4Resolver:       l4Resolver(b, ep.Id, "127.0.0.1:1"),
		GlobalStore:      config.NewGlobalRegistry(filepath.Join(b.TempDir(), "global.json")),
	}
	wg := &syncutil.WaitGroup{}
	startTCPServer(addr, ep, deps, wg, reg) // binds before it returns
	return addr, func() {
		reg.ShutdownAll(b.Context())
		wg.Wait()
	}
}
