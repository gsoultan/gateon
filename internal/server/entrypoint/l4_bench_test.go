// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package entrypoint

// Benchmarks for the path a plaintext TCP entrypoint gives an L4 route: accept,
// protocol inspection, route resolution, the backend dial and the copy in both
// directions. Everything is real except the backend, which is a loopback
// server in the same process: an l4.Resolver over route and service
// registries, the TCPBackendPool it builds, and the phantom core cmd/gateon
// always installs. Run on Linux with scripts/bench-datapath.sh.

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"syscall"
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

// benchBackend serves handle on a loopback listener until stop.
func benchBackend(b *testing.B, handle func(net.Conn)) (addr string, stop func()) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
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
func l4Resolver(b *testing.B, epID, backend string) L4Resolver {
	b.Helper()
	dir := b.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	svc := &gateonv1.Service{
		Id:              "bench-svc",
		Name:            "bench-svc",
		BackendType:     "tcp",
		WeightedTargets: []*gateonv1.Target{{Url: "tcp://" + backend, Weight: 1}},
	}
	if err := services.Update(context.Background(), svc); err != nil {
		b.Fatalf("add service: %v", err)
	}
	rt := &gateonv1.Route{Id: "bench-route", Type: "tcp", Entrypoints: []string{epID}, ServiceId: svc.Id}
	if err := routes.Update(context.Background(), rt); err != nil {
		b.Fatalf("add route: %v", err)
	}
	return WrapL4Resolver(l4.NewResolver(routes, services))
}

// tcpEntrypoint starts a plaintext TCP entrypoint whose one route leads to
// backend, and returns its address.
func tcpEntrypoint(b *testing.B, backend string) (addr string, stop func()) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("reserve port: %v", err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()

	ep := &gateonv1.EntryPoint{
		Id:        "bench-tcp",
		Address:   addr,
		Type:      gateonv1.EntryPoint_TCP,
		Protocols: []gateonv1.EntryPoint_Protocol{gateonv1.EntryPoint_TCP_PROTO},
	}
	reg := &ShutdownRegistry{}
	deps := &Deps{
		TLSManager:       gtls.NewManager(gtls.Config{}),
		Limiter:          traffic.NoopRateLimiter{},
		ShutdownRegistry: reg,
		L4Resolver:       l4Resolver(b, ep.Id, backend),
		GlobalStore:      config.NewGlobalRegistry(filepath.Join(b.TempDir(), "global.json")),
		Phantom:          phantom.NewPhantomCore(nil),
	}
	wg := &syncutil.WaitGroup{}
	startTCPServer(addr, ep, deps, wg, reg) // binds before it returns
	return addr, func() {
		reg.ShutdownAll(context.Background())
		wg.Wait()
	}
}

func benchCPU(b *testing.B) time.Duration {
	b.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		b.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func reportBenchCPU(b *testing.B, start time.Duration) {
	b.Helper()
	b.ReportMetric(float64(benchCPU(b)-start)/float64(b.N), "cpu-ns/op")
}

func echoConn(c net.Conn) { _, _ = io.Copy(c, c) }

// BenchmarkTCPEntrypointSession is one short L4 session per operation: connect,
// a 64-byte message the client speaks first, its echo, close. It is the
// per-connection cost of the entrypoint: accept, inspection, resolution, dial.
func BenchmarkTCPEntrypointSession(b *testing.B) {
	backend, stopBackend := benchBackend(b, echoConn)
	defer stopBackend()
	addr, stop := tcpEntrypoint(b, backend)
	defer stop()
	msg := []byte("bench-session-0123456789abcdefghijklmnopqrstuvwxyz-0123456789\r\n")
	buf := make([]byte, len(msg))

	b.ReportAllocs()
	start := benchCPU(b)
	for b.Loop() {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		if _, err := c.Write(msg); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(c, buf); err != nil {
			b.Fatalf("echo: %v", err)
		}
		_ = c.Close()
	}
	reportBenchCPU(b, start)
}

const benchBulk = 1 << 20

// BenchmarkTCPEntrypointThroughput moves 1 MiB per operation over one session
// through the entrypoint: client to backend (upload) and back (download).
func BenchmarkTCPEntrypointThroughput(b *testing.B) {
	b.Run("upload", func(b *testing.B) {
		benchEntrypointBulk(b, sinkThenAck, make([]byte, benchBulk), make([]byte, 1))
	})
	b.Run("download", func(b *testing.B) {
		benchEntrypointBulk(b, sendOnRequest, []byte{1}, make([]byte, benchBulk))
	})
}

// benchEntrypointBulk runs one session through the entrypoint to a backend
// running handle, and times writing send and reading len(recv) back.
func benchEntrypointBulk(b *testing.B, handle func(net.Conn), send, recv []byte) {
	backend, stopBackend := benchBackend(b, handle)
	defer stopBackend()
	addr, stop := tcpEntrypoint(b, backend)
	defer stop()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	defer c.Close()

	b.SetBytes(benchBulk)
	b.ReportAllocs()
	start := benchCPU(b)
	for b.Loop() {
		if _, err := c.Write(send); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(c, recv); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
	reportBenchCPU(b, start)
}

// sinkThenAck reads benchBulk bytes and acknowledges each batch with one byte.
func sinkThenAck(c net.Conn) {
	ack := []byte{1}
	for {
		if _, err := io.CopyN(io.Discard, c, benchBulk); err != nil {
			return
		}
		if _, err := c.Write(ack); err != nil {
			return
		}
	}
}

// sendOnRequest answers each one-byte request with benchBulk bytes.
func sendOnRequest(c net.Conn) {
	req := make([]byte, 1)
	payload := make([]byte, benchBulk)
	for {
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		if _, err := c.Write(payload); err != nil {
			return
		}
	}
}
