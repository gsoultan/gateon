// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package phantom

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/gsoultan/gateon/pkg/l4"
)

// liveL4Session opens one session through an l4.TCPBackendPool -- the proxy a
// TCP entrypoint's route uses -- to a backend that echoes, and returns a
// function that ends it and waits until the proxy has returned.
func liveL4Session(t *testing.T) (end func()) {
	t.Helper()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	echoed := make(chan struct{})
	t.Cleanup(func() {
		_ = backend.Close() // ends an Accept the proxy never reached
		<-echoed
	})
	go func() {
		defer close(echoed)
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen front: %v", err)
	}
	t.Cleanup(func() { _ = front.Close() })
	client, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	accepted, err := front.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	pool := l4.NewTCPBackendPool([]string{backend.Addr().String()}, "round_robin", 10000, 1000, false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pool.ProxyTCP(context.Background(), accepted)
	}()
	// One echoed byte: the proxy has dialed and both directions are running.
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := io.ReadFull(client, make([]byte, 1)); err != nil {
		t.Fatalf("echo: %v", err)
	}
	return func() {
		_ = client.Close()
		<-done
	}
}

// TestStatusReportsSpliceWithItsLiveSessions: on Linux a plaintext L4
// session is spliced by the kernel (see pkg/l4), so the Diagnostics card says
// so, and its count is the sessions actually being spliced -- not a number
// that stays at zero, as the AF_XDP "redirections" did.
func TestStatusReportsSpliceWithItsLiveSessions(t *testing.T) {
	core := NewPhantomCore()
	enabled, engine, sessions := core.GetStatus()
	if !enabled || engine != spliceEngine {
		t.Fatalf("GetStatus = (%v, %q), want (true, %q): L4 sessions here are spliced",
			enabled, engine, spliceEngine)
	}
	if sessions != 0 {
		t.Fatalf("%d spliced sessions before any session opened", sessions)
	}

	end := liveL4Session(t)
	if _, _, sessions = core.GetStatus(); sessions != 1 {
		t.Errorf("%d spliced sessions while one plaintext session is open, want 1", sessions)
	}
	end()
	if _, _, sessions = core.GetStatus(); sessions != 0 {
		t.Errorf("%d spliced sessions after the only session ended, want 0", sessions)
	}
}
