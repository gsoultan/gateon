// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

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
