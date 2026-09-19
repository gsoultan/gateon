// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestProxyTCPClosesClientWhenSessionEnds pins who owns the client socket.
// ProxyTCP closes it on every error path, but on the normal path it only
// half-closed it and returned, and the plaintext entrypoint that calls it does
// not close it either. The descriptor then lived until the garbage collector
// happened to finalise the net.Conn -- a per-connection leak on exactly the
// entrypoint that handles the most short-lived connections.
//
// Real sockets, not net.Pipe: the property under test is the state of a file
// descriptor, and a pipe has none.
func TestProxyTCPClosesClientWhenSessionEnds(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		_ = c.Close() // the backend hangs up as soon as it is reached
	}()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen front: %v", err)
	}
	t.Cleanup(func() { _ = front.Close() })

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		c, err := net.Dial("tcp", front.Addr().String())
		if err != nil {
			t.Errorf("dial front: %v", err)
			return
		}
		// The client has nothing to send; it half-closes and waits for the
		// proxy to finish with it.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
	}()

	srv, err := front.Accept()
	if err != nil {
		t.Fatalf("accept front: %v", err)
	}

	p := NewTCPBackendPool([]string{backend.Addr().String()}, "round_robin", 10000, 100, false)
	p.ProxyTCP(context.Background(), srv)
	<-clientDone

	// A second Close on a closed socket reports net.ErrClosed; on a socket
	// that was merely half-closed it succeeds, which is the leak.
	if err := srv.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ProxyTCP returned without closing the client connection: Close() = %v, want %v", err, net.ErrClosed)
	}
}
