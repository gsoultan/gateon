// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package phantom

import (
	"context"
	"net"
	"testing"
	"time"
)

// ProxyL4 splices a client and a backend together in both directions and waits
// for both to finish.
//
// These go through NewPhantomCore rather than naming an implementation, so they
// are not a test of the non-Linux fallback: on Linux they exercise linuxCore's
// proxyWithSplice, which is the path that ships. GATEON_XDP_IFACE is unset in a
// test environment, so ProxyL4 goes straight to the splice path. Both
// implementations had the same defect and took the same fix, and this runs
// against whichever one was built.

// idleBackend accepts one connection and then does nothing with it: it neither
// sends nor closes. That is not a broken server, it is any protocol where the
// server speaks only when spoken to and holds the connection open between
// requests.
func idleBackend(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held <- c // keep it open and silent
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		close(held)
		for c := range held {
			_ = c.Close()
		}
	}
}

// TestProxyL4ReturnsWhenTheClientDisconnects is the leak.
//
// The two directions are waited on together: the caller's copy ends when the
// client stops, and `<-done` then waits for the backend-to-client copy, which
// ends when the *backend* stops. A client that disconnects while the backend
// holds its side open leaves that second copy blocked on a read that will never
// return -- so `<-done` never returns either, and because the Close calls are
// deferred behind it, neither connection is ever closed.
//
// One goroutine and two sockets per disconnected client, held for the life of
// the process, on a path whose whole purpose is high connection volume.
func TestProxyL4ReturnsWhenTheClientDisconnects(t *testing.T) {
	backendAddr, stopBackend := idleBackend(t)
	defer stopBackend()

	// A socket pair standing in for the accepted client connection.
	clientSide, proxySide := net.Pipe()

	core := NewPhantomCore(nil)
	returned := make(chan error, 1)
	go func() {
		returned <- core.ProxyL4(context.Background(), proxySide, backendAddr)
	}()

	// The client goes away without the backend saying anything.
	_ = clientSide.Close()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyL4 did not return within 2s of the client disconnecting.\n" +
			"The backend-to-client copy is still blocked reading from a backend " +
			"that has nothing to say, and the Close calls are deferred behind the " +
			"wait for it — so this goroutine and both sockets are held for the " +
			"life of the process. One per disconnected client, on the L4 path.")
	}
}

// TestProxyL4ReturnsWhenTheBackendDisconnects is the mirror image.
//
// The same structure fails the other way: if the backend closes first and the
// client idles, the client-to-backend copy blocks instead.
func TestProxyL4ReturnsWhenTheBackendDisconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close() // greet nobody, hang up immediately
	}()

	clientSide, proxySide := net.Pipe()
	defer clientSide.Close()

	core := NewPhantomCore(nil)
	returned := make(chan error, 1)
	go func() {
		returned <- core.ProxyL4(context.Background(), proxySide, ln.Addr().String())
	}()

	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyL4 did not return within 2s of the backend hanging up; the " +
			"client-to-backend copy is blocked on a client that is simply idle, " +
			"which is not a fault condition")
	}
}

// TestProxyL4CopiesBothDirections is the control.
//
// Unblocking a stuck copy by closing the peer must not truncate a live one.
func TestProxyL4CopiesBothDirections(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	echoed := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		n, _ := c.Read(buf)
		echoed <- string(buf[:n])
		_, _ = c.Write([]byte("world"))
	}()

	clientSide, proxySide := net.Pipe()
	core := NewPhantomCore(nil)
	go func() { _ = core.ProxyL4(context.Background(), proxySide, ln.Addr().String()) }()

	go func() { _, _ = clientSide.Write([]byte("hello")) }()

	select {
	case got := <-echoed:
		if got != "hello" {
			t.Errorf("the backend received %q, want \"hello\"", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the backend never received the client's bytes")
	}

	_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	n, err := clientSide.Read(buf)
	if err != nil || string(buf[:n]) != "world" {
		t.Errorf("the client read %q (err %v), want \"world\" — closing the peer to "+
			"unblock a stuck copy must not truncate a live one", string(buf[:n]), err)
	}
	_ = clientSide.Close()
}
