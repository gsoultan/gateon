// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package entrypoint

import (
	"context"
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

// BenchmarkHTTPEntrypointConnection is one HTTP/1.1 request per operation,
// each on a connection of its own, through a plaintext HTTP entrypoint started
// the way cmd/gateon starts one: accept, the entrypoint's chain, close. What a
// connection costs the entrypoint is what its max_connections accounting adds
// to (ADR 0032). It uses only fixtures older than that change, so it runs
// against the tree before it as well.
func BenchmarkHTTPEntrypointConnection(b *testing.B) {
	withTelemetryStore(b)
	capture := &addrCapture{addrs: make(chan net.Addr, 1)}
	deps := &Deps{
		BaseHandler:      http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		Wrapped:          &mockGRPCWeb{},
		TLSManager:       gtls.NewManager(gtls.Config{}),
		Limiter:          traffic.NoopRateLimiter{},
		ShutdownRegistry: &ShutdownRegistry{},
		GlobalStore:      config.NewGlobalRegistry(filepath.Join(b.TempDir(), "global.json")),
		Phantom:          capture,
	}
	ep := &gateonv1.EntryPoint{Id: "bench-http", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP}
	wg := &syncutil.WaitGroup{}
	(&httpRunner{}).Run(context.Background(), ep, deps, wg)
	defer func() {
		deps.ShutdownRegistry.ShutdownAll(b.Context())
		wg.Wait()
	}()
	addr := (<-capture.addrs).String()
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
