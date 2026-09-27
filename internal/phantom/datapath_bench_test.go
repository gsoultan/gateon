// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build unix

package phantom

// Benchmarks for the data path the Phantom core puts in front of traffic: the
// listener OptimizeListener hands back, and ProxyL4. They are what an
// "accelerated" engine has to beat to be worth switching on, measured the same
// way for every engine so benchstat can compare two runs:
//
//	scripts/bench-datapath.sh    # Linux, two CPUs, see its header
//
// The io_uring listener was measured with exactly these and removed; the
// numbers are in the commit that removed it.
//
// Every benchmark also reports cpu-ns/op, the process's user plus system CPU
// time per operation from getrusage. Wall time alone flatters an engine that is
// fast only because it keeps a core busy polling; CPU per operation does not.
//
// Client, proxy and backend share the process, so cpu-ns/op includes the
// client's and the backend's work. That work is the same whichever engine is
// under test, so the difference between two runs is the engine's.

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// benchShared is the one core every benchmark here measures, built once per
// process the way cmd/gateon builds it.
var benchShared struct {
	once sync.Once
	core PhantomCore
}

// benchCore returns the core under measurement. An engine that can fall back
// must fail here when it does, rather than publish the fallback's numbers
// under its own name; the io_uring one could, and did, without a word.
func benchCore(b *testing.B) PhantomCore {
	b.Helper()
	benchShared.once.Do(func() { benchShared.core = NewPhantomCore() })
	return benchShared.core
}

// processCPU is the user plus system CPU time the process has used so far.
func processCPU(b *testing.B) time.Duration {
	b.Helper()
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		b.Fatalf("getrusage: %v", err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// reportCPU records the CPU the process used per operation since start.
func reportCPU(b *testing.B, start time.Duration) {
	b.Helper()
	b.ReportMetric(float64(processCPU(b)-start)/float64(b.N), "cpu-ns/op")
}

var okBody = []byte("ok")

// serveHTTP serves a two-byte response through the listener core hands back.
// stop closes the server and waits for its accept loop to return.
func serveHTTP(b *testing.B, core PhantomCore) (addr string, stop func()) {
	b.Helper()
	ln := listenLoopback(b)
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(okBody) }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(core.OptimizeListener(ln))
	}()
	return ln.Addr().String(), func() { stopAccepting(b, srv.Close, served) }
}

// stopAccepting calls closeFn and waits until the accept loop has returned. A
// listener whose Close does not end a pending Accept fails here instead of
// hanging the run; the io_uring one needed a connection to complete its
// accept before it would stop.
func stopAccepting(b *testing.B, closeFn func() error, served <-chan struct{}) {
	b.Helper()
	_ = closeFn()
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		b.Fatal("the accept loop did not return within 10s of its listener closing")
	}
}

func listenLoopback(b *testing.B) net.Listener {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	return ln
}

func dialLoopback(b *testing.B, addr string) net.Conn {
	b.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		b.Fatalf("dial %s: %v", addr, err)
	}
	return c
}

var getRequest = []byte("GET / HTTP/1.1\r\nHost: bench\r\n\r\n")

// countingReader counts what passes through it, so the benchmark can learn the
// exact length of one response and then read exactly that much per request
// without parsing HTTP in the timed loop.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// firstResponse sends one request on conn, checks the answer, and returns the
// number of bytes the whole response took on the wire.
func firstResponse(b *testing.B, conn net.Conn) int {
	b.Helper()
	if _, err := conn.Write(getRequest); err != nil {
		b.Fatalf("write request: %v", err)
	}
	cr := &countingReader{r: conn}
	resp, err := http.ReadResponse(bufio.NewReader(cr), nil)
	if err != nil {
		b.Fatalf("read response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != string(okBody) {
		b.Fatalf("response = %d %q (%v), want 200 %q", resp.StatusCode, body, err, okBody)
	}
	return cr.n
}

// roundTrip writes msg and reads len(buf) bytes back.
func roundTrip(conn net.Conn, msg, buf []byte) error {
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	_, err := io.ReadFull(conn, buf)
	return err
}

// BenchmarkHTTPRoundTrip is one small request and response on a keep-alive
// connection: the latency of the listener's read and write path.
func BenchmarkHTTPRoundTrip(b *testing.B) {
	addr, stop := serveHTTP(b, benchCore(b))
	defer stop()
	conn := dialLoopback(b, addr)
	defer conn.Close()
	buf := make([]byte, firstResponse(b, conn))

	b.ReportAllocs()
	start := processCPU(b)
	for b.Loop() {
		if err := roundTrip(conn, getRequest, buf); err != nil {
			b.Fatalf("round trip: %v", err)
		}
	}
	reportCPU(b, start)
}

// BenchmarkHTTPRoundTripParallel is the same request from many connections at
// once, the shape batching engines claim to win: ns/op is the inverse of
// requests per second.
func BenchmarkHTTPRoundTripParallel(b *testing.B) {
	addr, stop := serveHTTP(b, benchCore(b))
	defer stop()
	probe := dialLoopback(b, addr)
	respLen := firstResponse(b, probe)
	_ = probe.Close()

	b.SetParallelism(16)
	b.ReportAllocs()
	start := processCPU(b)
	b.RunParallel(func(pb *testing.PB) {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			b.Errorf("dial: %v", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, respLen)
		for pb.Next() {
			if err := roundTrip(conn, getRequest, buf); err != nil {
				b.Errorf("round trip: %v", err)
				return
			}
		}
	})
	reportCPU(b, start)
}

// BenchmarkHTTPConnectRoundTrip opens a connection per request: accept, one
// request, one response, close. It is the accept path's cost.
//
// The client reads the response by its length and hangs up, rather than
// sending Connection: close and reading to EOF, because under the io_uring
// listener that response never ended (it ignored the read deadline net/http
// ends its background read with). Kept so later runs compare with its numbers.
func BenchmarkHTTPConnectRoundTrip(b *testing.B) {
	addr, stop := serveHTTP(b, benchCore(b))
	defer stop()
	probe := dialLoopback(b, addr)
	buf := make([]byte, firstResponse(b, probe))
	_ = probe.Close()

	b.ReportAllocs()
	start := processCPU(b)
	for b.Loop() {
		conn := dialLoopback(b, addr)
		if err := roundTrip(conn, getRequest, buf); err != nil {
			b.Fatalf("round trip: %v", err)
		}
		_ = conn.Close()
	}
	reportCPU(b, start)
}

// BenchmarkIdleCPU is what the core costs with nothing to do: a served listener
// and no traffic. Each operation is 10ms of wall time, so ns/op means nothing
// here; cpu-ms/s is the CPU the whole process used per second of idling.
func BenchmarkIdleCPU(b *testing.B) {
	_, stop := serveHTTP(b, benchCore(b))
	defer stop()

	start := processCPU(b)
	began := time.Now()
	for b.Loop() {
		time.Sleep(10 * time.Millisecond) // the idle window itself, not a wait for a condition
	}
	elapsed := time.Since(began)
	b.ReportMetric(float64(processCPU(b)-start)/float64(elapsed)*1e3, "cpu-ms/s")
}

// serveTCP runs handle for every connection to a plain loopback listener: the
// backend, which is the same for every engine. stop closes the listener and
// waits for the handlers, which return when the proxy closes its side.
func serveTCP(b *testing.B, handle func(net.Conn)) (addr string, stop func()) {
	b.Helper()
	ln := listenLoopback(b)
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

// proxyFront accepts on the listener core hands back and gives each connection
// to ProxyL4 with target as the backend.
func proxyFront(b *testing.B, core PhantomCore, target string) (addr string, stop func()) {
	b.Helper()
	ln := listenLoopback(b)
	l := core.OptimizeListener(ln)
	var sessions sync.WaitGroup
	var closing atomic.Bool
	served := make(chan struct{})
	go func() {
		defer close(served)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if closing.Load() {
				_ = c.Close()
				return
			}
			sessions.Go(func() { _ = core.ProxyL4(context.Background(), c, target) })
		}
	}()
	return ln.Addr().String(), func() {
		closing.Store(true)
		stopAccepting(b, l.Close, served)
		sessions.Wait()
	}
}

func echo(c net.Conn) { _, _ = io.Copy(c, c) }

const bulk = 1 << 20

// sinkWithAck reads bulk bytes and acknowledges each with one byte.
func sinkWithAck(c net.Conn) {
	ack := []byte{1}
	for {
		if _, err := io.CopyN(io.Discard, c, bulk); err != nil {
			return
		}
		if _, err := c.Write(ack); err != nil {
			return
		}
	}
}

// sourceOnRequest answers each one-byte request with bulk bytes.
func sourceOnRequest(c net.Conn) {
	req := make([]byte, 1)
	payload := make([]byte, bulk)
	for {
		if _, err := io.ReadFull(c, req); err != nil {
			return
		}
		if _, err := c.Write(payload); err != nil {
			return
		}
	}
}

// proxiedConn is a client connection through ProxyL4 to a backend running
// handle, with the proxy session already established.
func proxiedConn(b *testing.B, handle func(net.Conn)) (conn net.Conn, stop func()) {
	b.Helper()
	backend, stopBackend := serveTCP(b, handle)
	front, stopFront := proxyFront(b, benchCore(b), backend)
	conn = dialLoopback(b, front)
	return conn, func() {
		_ = conn.Close()
		stopFront()
		stopBackend()
	}
}

// BenchmarkL4Echo is a 64-byte request and its echo through ProxyL4: the L4
// path's latency for small messages.
func BenchmarkL4Echo(b *testing.B) {
	conn, stop := proxiedConn(b, echo)
	defer stop()
	msg, buf := make([]byte, 64), make([]byte, 64)
	if err := roundTrip(conn, msg, buf); err != nil { // the session is up
		b.Fatalf("first round trip: %v", err)
	}

	b.ReportAllocs()
	start := processCPU(b)
	for b.Loop() {
		if err := roundTrip(conn, msg, buf); err != nil {
			b.Fatalf("round trip: %v", err)
		}
	}
	reportCPU(b, start)
}

// BenchmarkL4Throughput moves 1 MiB per operation through ProxyL4, client to
// backend (upload) and backend to client (download): one direction of the
// proxy each.
func BenchmarkL4Throughput(b *testing.B) {
	b.Run("upload", func(b *testing.B) {
		conn, stop := proxiedConn(b, sinkWithAck)
		defer stop()
		payload, ack := make([]byte, bulk), make([]byte, 1)
		b.SetBytes(bulk)
		b.ReportAllocs()
		start := processCPU(b)
		for b.Loop() {
			if err := roundTrip(conn, payload, ack); err != nil {
				b.Fatalf("upload: %v", err)
			}
		}
		reportCPU(b, start)
	})
	b.Run("download", func(b *testing.B) {
		conn, stop := proxiedConn(b, sourceOnRequest)
		defer stop()
		req, payload := []byte{1}, make([]byte, bulk)
		b.SetBytes(bulk)
		b.ReportAllocs()
		start := processCPU(b)
		for b.Loop() {
			if err := roundTrip(conn, req, payload); err != nil {
				b.Fatalf("download: %v", err)
			}
		}
		reportCPU(b, start)
	})
}
