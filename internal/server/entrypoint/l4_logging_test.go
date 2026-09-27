// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// lockedBuffer is a log sink safe to write from the entrypoint's goroutines
// while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Len is how much has been logged so far, to read only what comes after.
func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

// captureLogsAt sends everything logged at level and above to the returned
// buffer: INFO is the level a production install logs at by default.
func captureLogsAt(t *testing.T, level slog.Level) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prevShim, prevDefault := logger.L, slog.Default()
	logger.L = &logger.SlogShim{}
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() {
		logger.L = prevShim
		slog.SetDefault(prevDefault)
	})
	return buf
}

// TestL4ConnectionsAreNotLoggedOneByOneAtInfo: at the default level, an L4
// session through a plaintext TCP entrypoint wrote an INFO line of its own,
// and a connection that hung up before sending anything -- every port scan --
// an ERROR line. On a busy or scanned entrypoint that is a log line per
// connection, each through stdout and the dashboard's log broadcaster, whose
// mutex every line takes; and ERROR for a client hanging up buries real
// errors. Per-connection detail is DEBUG.
func TestL4ConnectionsAreNotLoggedOneByOneAtInfo(t *testing.T) {
	// Installed before anything that logs runs: swapping the logger under a
	// running goroutine is a data race.
	logs := captureLogsAt(t, slog.LevelInfo)
	backend, stopBackend := serveBackend(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	defer stopBackend()
	addr, stop := plaintextTCPEntrypoint(t, backend)
	defer stop()
	// The first session builds the route's backend pool, which is logged once
	// and belongs to the configuration, not to any connection.
	echoThrough(t, addr, "warm\n")
	mark := logs.Len()

	for _, first := range []string{"hello\n", "SSH-2.0-OpenSSH_9.6\r\n"} {
		echoThrough(t, addr, first)
	}
	probe, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = probe.Close() // a scanner: connect, send nothing, hang up
	stop()            // waits for every connection's goroutine, so all of them have logged

	if got := strings.TrimSpace(logs.String()[mark:]); got != "" {
		t.Fatalf("two L4 sessions and one probe logged at INFO or above:\n%s", got)
	}
}

// TestL4RoutingIsStillLoggedAtDebug: the per-connection detail moved to DEBUG,
// it did not disappear -- including the protocol that chose the route, which
// the INFO lines used to carry.
func TestL4RoutingIsStillLoggedAtDebug(t *testing.T) {
	logs := captureLogsAt(t, slog.LevelDebug)
	backend, stopBackend := serveBackend(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	defer stopBackend()
	addr, stop := plaintextTCPEntrypoint(t, backend)
	defer stop()

	echoThrough(t, addr, "SSH-2.0-OpenSSH_9.6\r\n")
	stop()

	got := logs.String()
	if !strings.Contains(got, `msg="TCP inspection: route found, proxying"`) || !strings.Contains(got, "protocol=ssh") {
		t.Fatalf("an SSH session through the entrypoint left no DEBUG line naming its route's protocol:\n%s", got)
	}
}

// echoThrough sends first through the entrypoint and waits for its echo.
func echoThrough(t *testing.T, addr, first string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, first); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, make([]byte, len(first))); err != nil {
		t.Fatalf("echo of %q: %v", first, err)
	}
}
