// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package entrypoint

// Benchmarks for the path a plaintext TCP entrypoint gives an L4 route: accept,
// protocol inspection, route resolution, the backend dial and the copy in both
// directions. Everything is real except the backend, which is a loopback
// server in the same process: an l4.Resolver over route and service
// registries, the TCPBackendPool it builds, and the phantom core cmd/gateon
// always installs (fixtures in l4_session_test.go). Run on Linux with
// scripts/bench-datapath.sh.

import (
	"crypto/tls"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

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

// BenchmarkTLSEntrypointSession is one short session through a TCP entrypoint
// that terminates TLS: a full handshake, a 64-byte echo, close. These sessions
// cannot splice; the proxy copies the decrypted bytes through buffers.
func BenchmarkTLSEntrypointSession(b *testing.B) {
	backend, stopBackend := serveBackend(b, echoConn)
	defer stopBackend()
	serverTLS, clientTLS := selfSignedTLS(b)
	addr, stop := l4Entrypoint(b, backend, serverTLS)
	defer stop()
	msg, buf := make([]byte, 64), make([]byte, 64)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	b.ReportAllocs()
	start := benchCPU(b)
	for b.Loop() {
		c, err := tls.DialWithDialer(dialer, "tcp", addr, clientTLS)
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

// BenchmarkTCPEntrypointSession is one short L4 session per operation: connect,
// a 64-byte message the client speaks first, its echo, close. It is the
// per-connection cost of the entrypoint: accept, inspection, resolution, dial.
func BenchmarkTCPEntrypointSession(b *testing.B) {
	backend, stopBackend := serveBackend(b, echoConn)
	defer stopBackend()
	addr, stop := plaintextTCPEntrypoint(b, backend)
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
	backend, stopBackend := serveBackend(b, handle)
	defer stopBackend()
	addr, stop := plaintextTCPEntrypoint(b, backend)
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
