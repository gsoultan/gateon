// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/syncutil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// shutdownBound is how long a test waits for a shutdown that was handed a
// deadline far shorter than this. It is a failure timeout, not a poll: a
// shutdown that honours its deadline returns long before it, and one that
// does not never returns at all.
const shutdownBound = 10 * time.Second

// shutdownWithin runs ShutdownAll with a short deadline and fails the test if
// it has not returned well after that deadline passed.
func shutdownWithin(t *testing.T, reg *ShutdownRegistry, deadline time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	done := make(chan struct{})
	go func() {
		reg.ShutdownAll(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownBound):
		t.Fatalf("ShutdownAll was given %v and had not returned after %v: "+
			"SIGTERM would hang here until the process is killed, so nothing "+
			"after the listeners -- telemetry flush, database close -- ever runs",
			deadline, shutdownBound)
	}
}

// TestSharedHTTPServerShutdownReturns covers the HTTP server a plaintext TCP
// entrypoint creates the first time its inspector sees an HTTP request.
//
// That server is fed by a channel-backed listener. http.Server.Shutdown closes
// its listeners and then waits -- without consulting its context -- for every
// Serve loop to return, and Serve only returns once Accept does. A listener
// whose Close does not unblock Accept therefore makes Shutdown wait forever,
// whatever deadline it was given.
func TestSharedHTTPServerShutdownReturns(t *testing.T) {
	deps := mockDepsForInspection(t)
	ep := &gateonv1.EntryPoint{Id: "smart-tcp", Type: gateonv1.EntryPoint_TCP}

	client, server := net.Pipe()
	defer client.Close()
	serveConnAsHTTP(server, nil, ep, deps)

	// One full request/response proves the shared server is serving, and it
	// registers its shutdown hook before it starts to.
	go func() {
		_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: gw\r\nConnection: close\r\n\r\n")
	}()
	_ = client.SetReadDeadline(time.Now().Add(shutdownBound))
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("no response through the shared server: %v", err)
	}
	_ = resp.Body.Close()

	shutdownWithin(t, deps.ShutdownRegistry, 200*time.Millisecond)
}

// TestShutdownAllGivesEveryServerTheWholeWindow pins what the shared deadline
// means: each registered server gets to drain against it, not whatever the
// servers registered before it left over.
//
// The first function stands in for the management listener with a dashboard
// tab open: its stream never ends on its own, so it uses the entire window.
// ShutdownAll used to call the functions in turn, so every entrypoint
// registered after it kept its listener open and accepting for the whole 30s
// and was then handed an expired context -- closed with no drain at all.
func TestShutdownAllGivesEveryServerTheWholeWindow(t *testing.T) {
	reg := &ShutdownRegistry{}
	firstDone := make(chan struct{})
	reg.Register(func(ctx context.Context) error {
		defer close(firstDone)
		<-ctx.Done()
		return ctx.Err()
	})
	secondCalled := make(chan error, 1)
	reg.Register(func(ctx context.Context) error {
		secondCalled <- ctx.Err()
		return nil
	})

	shutdownWithin(t, reg, 300*time.Millisecond)

	select {
	case err := <-secondCalled:
		if err != nil {
			t.Fatalf("the second server was asked to shut down with a context that had "+
				"already expired (%v): it could not drain anything, and its listener "+
				"stayed open while the first server used the whole window", err)
		}
	default:
		t.Fatal("ShutdownAll returned without shutting down the second server")
	}
	select {
	case <-firstDone:
	default:
		t.Fatal("ShutdownAll returned before the first server finished shutting down")
	}
}

// addrCapture is a PhantomCore whose only job is to report the address each
// listener was bound to, so a test can start an entrypoint on port 0 and still
// know where to connect.
type addrCapture struct{ addrs chan net.Addr }

func (a *addrCapture) ProxyL4(context.Context, net.Conn, string) error {
	return errors.New("addrCapture does not proxy")
}

func (a *addrCapture) OptimizeListener(l net.Listener) net.Listener {
	a.addrs <- l.Addr()
	return l
}

// stream is the observable life of one long-lived request: entered fires when
// the handler starts serving it, ended when the handler gives up on it.
type stream struct {
	entered chan struct{}
	ended   chan struct{}
}

// streamingDeps returns entrypoint dependencies whose base handler behaves like
// a server-sent-events stream: it answers, flushes, reports that it is running
// and then holds the request open until the request's context ends. Nothing
// but the connection closing ends it, which is what an open dashboard tab or a
// proxied event stream looks like to a shutting-down server.
func streamingDeps(t *testing.T) (*Deps, *addrCapture, stream) {
	t.Helper()
	s := stream{entered: make(chan struct{}, 1), ended: make(chan struct{}, 1)}
	deps := mockDepsForInspection(t)
	deps.GlobalStore = config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
	capture := &addrCapture{addrs: make(chan net.Addr, 1)}
	deps.Phantom = capture
	deps.BaseHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		s.entered <- struct{}{}
		<-r.Context().Done()
		s.ended <- struct{}{}
	})
	return deps, capture, s
}

// streamEnded fails the test unless the long-lived request was ended by the
// shutdown -- a deadline that returns while the request keeps running has
// bounded the wait, not the work.
func streamEnded(t *testing.T, s stream) {
	t.Helper()
	select {
	case <-s.ended:
	case <-time.After(shutdownBound):
		t.Fatal("shutdown returned but the in-flight stream is still being served: " +
			"past the deadline the server has to close what it could not drain")
	}
}

// openStream starts a long-lived request against addr and returns once the
// handler is running it.
func openStream(t *testing.T, addr net.Addr, entered <-chan struct{}) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr.String(), shutdownBound)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	req := "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(shutdownBound):
		t.Fatal("the stream never reached the handler")
	}
}

// waitWithin fails the test if the entrypoint's goroutines are still running
// well after shutdown returned.
func waitWithin(t *testing.T, wg *syncutil.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownBound):
		t.Fatal("entrypoint goroutines still running after shutdown returned")
	}
}

// TestHTTPServersShutdownHonourTheirDeadline covers the two plain http.Servers
// Run starts: every HTTP entrypoint and the dedicated management listener.
//
// Both registered server.Shutdown(context.Background()), discarding the
// deadline ShutdownAll hands them. Shutdown waits for every active connection
// to go idle, so one request that does not end on its own -- an SSE stream,
// a stuck upload, a proxied backend that never answers -- held SIGTERM open
// indefinitely, and Run's 30s ShutdownTimeout bounded nothing.
func TestHTTPServersShutdownHonourTheirDeadline(t *testing.T) {
	t.Run("http_entrypoint", func(t *testing.T) {
		deps, capture, s := streamingDeps(t)
		ep := &gateonv1.EntryPoint{Id: "web", Address: "127.0.0.1:0", Type: gateonv1.EntryPoint_HTTP}
		wg := &syncutil.WaitGroup{}
		(&httpRunner{}).Run(context.Background(), ep, deps, wg)

		openStream(t, <-capture.addrs, s.entered)
		shutdownWithin(t, deps.ShutdownRegistry, 200*time.Millisecond)
		streamEnded(t, s)
		waitWithin(t, wg)
	})

	t.Run("management", func(t *testing.T) {
		for _, env := range []string{"GATEON_MANAGEMENT_BIND", "GATEON_MANAGEMENT_PORT",
			"GATEON_MANAGEMENT_ALLOWED_IPS", "GATEON_MANAGEMENT_HOST"} {
			t.Setenv(env, "")
		}
		deps, capture, s := streamingDeps(t)
		deps.ManagementConfig = &gateonv1.ManagementConfig{Bind: "127.0.0.1", Port: "0"}
		wg := &syncutil.WaitGroup{}
		startSecureManagementServer("0", deps, wg)

		openStream(t, <-capture.addrs, s.entered)
		shutdownWithin(t, deps.ShutdownRegistry, 200*time.Millisecond)
		streamEnded(t, s)
		waitWithin(t, wg)
	})
}
