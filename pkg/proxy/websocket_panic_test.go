// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// panickingReader stands for a reader wrapped around the client -- the WAF's
// WebSocket inspection -- that panics on what the client sent.
type panickingReader struct{}

func (panickingReader) Read([]byte) (int, error) { panic("inspection panicked on a client message") }

// TestTunnelUpgradeContainsClientReaderPanic holds a panic on the
// client-to-backend copy to the one tunnel. That copy runs on a goroutine
// tunnelUpgrade starts, outside net/http's recovery, so before the fix the
// panic ended the process: this test's binary exited with status 2.
func TestTunnelUpgradeContainsClientReaderPanic(t *testing.T) {
	client, clientPeer := net.Pipe()
	backend, backendPeer := net.Pipe()
	defer clientPeer.Close()
	defer backendPeer.Close()

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		tunnelUpgrade(client, panickingReader{}, backend, bufio.NewReader(backend))
	}()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnelUpgrade did not return after the client copy panicked")
	}
	for name, peer := range map[string]net.Conn{"client": clientPeer, "backend": backendPeer} {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("%s side: read err = %v; want the tunnel closed", name, err)
		}
	}
}
