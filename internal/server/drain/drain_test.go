// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package drain

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// testBound is a failure timeout, never a pause: everything here returns long
// before it when it works.
const testBound = 20 * time.Second

// served is one tracked server on a loopback port.
type served struct {
	addr     string
	listener net.Listener
	arrivals *Arrivals
	serveErr chan error
	// took is how long Shutdown itself ran, in nanoseconds. Measured around
	// the call, not around the test's own probing of the listener.
	took atomic.Int64
}

func serve(t *testing.T, connState func(net.Conn, http.ConnState)) *served {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "answered")
		}),
		ReadHeaderTimeout: testBound,
		ConnState:         connState,
	}
	s := &served{addr: ln.Addr().String(), listener: ln, arrivals: Track(srv), serveErr: make(chan error, 1)}
	go func() { s.serveErr <- s.arrivals.Serve(func() error { return srv.Serve(ln) }) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s
}

// connect opens a connection and returns once the server has accepted it.
func (s *served) connect(t *testing.T, want int64) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	eventually(t, "the server to accept the connection", func() bool { return s.arrivals.pending.Load() == want })
	return c
}

// shutdown starts Shutdown and returns once the listener has stopped
// accepting, which is the point after which the old code had already told
// net/http to drop whatever request came next.
func (s *served) shutdown(t *testing.T) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), testBound)
	t.Cleanup(cancel)
	go func() {
		began := time.Now()
		err := s.arrivals.Shutdown(ctx, s.listener)
		s.took.Store(int64(time.Since(began)))
		done <- err
	}()
	eventually(t, "the listener to stop accepting", func() bool {
		c, err := net.DialTimeout("tcp", s.addr, time.Second)
		if err != nil {
			return true
		}
		_ = c.Close()
		return false
	})
	return done
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(testBound)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func within(t *testing.T, what string, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(testBound):
		t.Fatalf("%s had not returned after %v", what, testBound)
		return nil
	}
}

// TestAConnectionAcceptedBeforeShutdownIsAnswered is the request a restart
// used to lose: the connection is in the server's hands, the shutdown begins,
// and then the request arrives. net/http closes such a connection without
// answering once it has been told to shut down, so the shutdown must not tell
// it until the request has been served.
func TestAConnectionAcceptedBeforeShutdownIsAnswered(t *testing.T) {
	s := serve(t, nil)
	c := s.connect(t, 1)
	done := s.shutdown(t)

	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: gateway\r\n\r\n"); err != nil {
		t.Fatalf("send the request: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(testBound))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("the connection was accepted before the shutdown and got no answer: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "answered" {
		t.Fatalf("got %d %q, want 200 \"answered\"", resp.StatusCode, body)
	}
	if err := within(t, "Shutdown", done); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := within(t, "Serve", s.serveErr); err != nil {
		t.Fatalf("Serve reported a shutdown as a failure: %v", err)
	}
}

// TestASilentConnectionHoldsShutdownOnlyForTheGrace: a connection that never
// sends a request must not hold the process open until its drain deadline, nor
// for the five seconds net/http would give it.
func TestASilentConnectionHoldsShutdownOnlyForTheGrace(t *testing.T) {
	s := serve(t, nil)
	c := s.connect(t, 1)
	if err := within(t, "Shutdown", s.shutdown(t)); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	took := time.Duration(s.took.Load())
	if took < FirstRequestGrace {
		t.Fatalf("Shutdown returned after %v, before the %v a connection is given to send its request", took, FirstRequestGrace)
	}
	if took >= 4*time.Second {
		t.Fatalf("Shutdown took %v for one silent connection; it was left to net/http's five seconds", took)
	}
	_ = c.SetReadDeadline(time.Now().Add(testBound))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the silent connection was left open by the shutdown")
	}
}

// TestAClosedConnectionIsNotWaitedFor: a client that connects and leaves owes
// nothing, and the caller's own ConnState hook still runs.
func TestAClosedConnectionIsNotWaitedFor(t *testing.T) {
	closed := make(chan struct{}, 1)
	s := serve(t, func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	})
	c := s.connect(t, 1)
	_ = c.Close()
	select {
	case <-closed:
	case <-time.After(testBound):
		t.Fatal("the server's own ConnState hook was not called")
	}
	eventually(t, "the arrival to be settled", func() bool { return s.arrivals.pending.Load() == 0 })

	if err := within(t, "Shutdown", s.shutdown(t)); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if took := time.Duration(s.took.Load()); took >= FirstRequestGrace {
		t.Fatalf("Shutdown took %v with nothing pending; it waited out the grace", took)
	}
}

// TestKeepAliveRequestsSettleOnce: the second request on a connection must
// not count the connection down a second time.
func TestKeepAliveRequestsSettleOnce(t *testing.T) {
	s := serve(t, nil)
	client := &http.Client{Timeout: testBound}
	t.Cleanup(client.CloseIdleConnections)
	for range 3 {
		resp, err := client.Get("http://" + s.addr + "/")
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if n := s.arrivals.pending.Load(); n != 0 {
		t.Fatalf("pending is %d after three answered requests on one connection, want 0", n)
	}
}

// BenchmarkAnsweredConnection is what tracking costs a request on a
// connection that has already been answered once, which is every request but
// a connection's first: one context lookup and one atomic load, no
// allocation.
func BenchmarkAnsweredConnection(b *testing.B) {
	srv := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	a := Track(srv)
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	ctx := srv.ConnContext(context.Background(), server)
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", http.NoBody)
	if err != nil {
		b.Fatal(err)
	}
	srv.Handler.ServeHTTP(nil, r)
	if n := a.pending.Load(); n != 0 {
		b.Fatalf("pending is %d after the first request, want 0", n)
	}
	b.ReportAllocs()
	for b.Loop() {
		srv.Handler.ServeHTTP(nil, r)
	}
}
