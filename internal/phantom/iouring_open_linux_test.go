// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding && linux

// These tests document defects in the io_uring listener/connection wrapper that
// a correct fix cannot make without a design decision (see phantom-report.md):
// the wrapper does not implement net.Listener/net.Conn lifecycle and deadline
// semantics, and the feature has no benchmark behind it while measuring far
// slower than the standard path. They are excluded from the normal build by the
// openfinding tag; run with: go test -tags openfinding -run OpenFinding.
package phantom

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestOpenFindingListenerCloseDoesNotUnblockAccept: net.Listener requires that
// Close unblock any Accept in progress. The io_uring Accept blocks on its
// completion channel and the core's context, neither of which the listener's
// Close touches, so http.Server.Shutdown -- which closes listeners and then
// waits for every Serve loop to return -- never returns, whatever deadline it
// was given. SIGTERM then hangs until the process is killed.
func TestOpenFindingListenerCloseDoesNotUnblockAccept(t *testing.T) {
	opt := listenOptimized(t, uringCore(t))
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = srv.Serve(opt) }()

	resp, err := http.Get("http://" + opt.Addr().String() + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	http.DefaultClient.CloseIdleConnections()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		done <- srv.Shutdown(ctx)
	}()
	select {
	case err := <-done:
		t.Logf("Shutdown returned: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("http.Server.Shutdown was given a 500ms context and had not returned " +
			"after 5s: the io_uring Accept is still blocked and Close did not wake it, " +
			"so SIGTERM hangs until the process is killed")
	}
}

// TestOpenFindingReadIgnoresDeadline: net.Conn requires SetReadDeadline to make
// a blocked Read return once the time passes. The io_uring Read never consults
// the deadline (it waits on a completion), so an idle or half-open connection
// pins its goroutine forever -- the very leak the ProxyL4 tests exist to
// prevent, reintroduced on the optimized listener.
func TestOpenFindingReadIgnoresDeadline(t *testing.T) {
	opt := listenOptimized(t, uringCore(t))
	server, client := acceptOne(t, opt)
	defer server.Close()
	defer client.Close()

	if err := server.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	res := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 16))
		res <- err
	}()
	select {
	case err := <-res:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Read after its deadline returned %v, want a timeout error", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Read ignored a 200ms read deadline for 3s: the io_uring read waits " +
			"on a completion and never consults the deadline, so an idle connection " +
			"holds its goroutine and socket for the life of the process")
	}
}
