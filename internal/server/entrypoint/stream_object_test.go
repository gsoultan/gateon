// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"io"
	"net"
	"net/http"
	"testing"
)

// TestAStoredObjectTypedAsAStreamIsCutAtTheWriteDeadline is DP-N7 at the
// listener. An app that serves objects under the type their uploader chose
// answered one with text/event-stream, and that alone lifted the response off
// the write deadline: a client reading nothing held the object, a goroutine
// and a backend connection for the stream lifetime (an hour at minimal). The
// object declares its length; an event stream never does. The request's
// Accept is sent and decides nothing, as ADR 0042 says.
func TestAStoredObjectTypedAsAStreamIsCutAtTheWriteDeadline(t *testing.T) {
	result := make(chan error, 1)
	object := writingHandler(result)
	addr := startDeadlineEP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "67108864")
		object.ServeHTTP(w, r)
	}))
	c := dialEP(t, addr)
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(4096)
	}
	if _, err := io.WriteString(c, "GET /uploads/x HTTP/1.1\r\nHost: app.example\r\nAccept: text/event-stream\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	endedWithError(t, result, "a 64 MiB stored object typed text/event-stream, to a client that reads nothing")
}
