// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package phantom

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestProxyL4LeavesTheClientUsableWhenItCannotOffload pins the ownership rule
// the entrypoint depends on.
//
// The plaintext TCP entrypoint attempts the L4 offload first and falls through
// to protocol inspection when it returns an error — the fall-through is the
// whole point of checking the error. But the offload closed the client before
// returning that error, so the caller went on to inspect and proxy a socket
// that was already gone, and the client saw its connection reset.
//
// It is reached with an empty target, because the entrypoint has not resolved
// a route at that point and passes "". Dialing "" always fails, so every
// connection on that path was destroyed before the inspector ever saw it.
//
// A function that reports "I did not handle this" must leave the thing it did
// not handle intact.
func TestProxyL4LeavesTheClientUsableWhenItCannotOffload(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()

	core := NewPhantomCore(nil)

	// "" is what the entrypoint passes when no route has been resolved yet.
	err := core.ProxyL4(context.Background(), client, "")
	if err == nil {
		t.Fatal("ProxyL4 reported success for an empty target address")
	}

	// The caller's contract: on error it keeps the connection and handles it
	// itself. So the socket has to still work.
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, rerr := peer.Read(buf)
		done <- rerr
	}()

	_ = client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, werr := client.Write([]byte("ping")); werr != nil {
		t.Fatalf("the client connection was closed by a failed offload attempt, so the "+
			"entrypoint's fall-through to inspection runs on a dead socket: %v", werr)
	}
	if rerr := <-done; rerr != nil {
		t.Fatalf("read after a failed offload attempt: %v", rerr)
	}
}
