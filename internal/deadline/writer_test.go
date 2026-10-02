// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsEventStream(t *testing.T) {
	for ct, want := range map[string]bool{
		"text/event-stream":                true,
		"Text/Event-Stream":                true,
		"text/event-stream; charset=utf-8": true,
		" text/event-stream":               true,
		"text/event-streamx":               false,
		"text/event":                       false,
		"text/html":                        false,
		"":                                 false,
		"application/text/event-stream":    false,
	} {
		if got := IsEventStream(ct); got != want {
			t.Errorf("IsEventStream(%q) = %v, want %v", ct, got, want)
		}
	}
}

// deadlineRecorder is a ResponseWriter that records the deadlines
// http.ResponseController sets on it.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	read, write []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.read = append(d.read, t)
	return nil
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.write = append(d.write, t)
	return nil
}

// serveThrough runs h behind a StreamWriter and returns what it set.
func serveThrough(h http.HandlerFunc, limits StreamLimits) (*deadlineRecorder, bool) {
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	sw := NewStreamWriter(rec, limits)
	defer Release(sw)
	h(sw, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec, sw.Streaming()
}

// TestStreamWriterLiftsOnlyWhatTheServerAnsweredAsAStream: the decision is
// the response's -- a 200 whose Content-Type is text/event-stream -- and
// nothing else: not another status, not another type, not a 1xx on the way.
func TestStreamWriterLiftsOnlyWhatTheServerAnsweredAsAStream(t *testing.T) {
	limits := StreamLimits{Idle: time.Minute, MaxLifetime: time.Hour}
	cases := []struct {
		name string
		h    http.HandlerFunc
		want bool
	}{
		{"event_stream", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
		}, true},
		{"implicit_200", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			_, _ = w.Write([]byte("data: x\n\n"))
		}, true},
		{"after_early_hints", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
		}, true},
		{"html", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
		}, false},
		{"error_typed_as_stream", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusBadGateway)
		}, false},
		{"type_set_after_status", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("x"))
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("y"))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, streaming := serveThrough(tc.h, limits)
			if streaming != tc.want {
				t.Fatalf("Streaming() = %v, want %v", streaming, tc.want)
			}
			moved := len(rec.read) > 0 || len(rec.write) > 0
			if moved != tc.want {
				t.Fatalf("deadlines moved = %v (read %v, write %v), want %v", moved, rec.read, rec.write, tc.want)
			}
		})
	}
}

// TestAStreamsDeadlinesAreItsBounds: once lifted, both deadlines are where
// the stream ends if nothing more moves -- the idle timeout from now, capped
// by the lifetime -- and neither is cleared.
func TestAStreamsDeadlinesAreItsBounds(t *testing.T) {
	limits := StreamLimits{Idle: time.Minute, MaxLifetime: time.Hour}
	before := time.Now()
	rec, _ := serveThrough(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}, limits)
	after := time.Now()
	for name, set := range map[string][]time.Time{"read": rec.read, "write": rec.write} {
		if len(set) != 1 {
			t.Fatalf("%s deadline set %d times, want once", name, len(set))
		}
		if d := set[0]; d.Before(before.Add(limits.Idle)) || d.After(after.Add(limits.Idle)) {
			t.Fatalf("%s deadline %v, want the idle timeout from when it was lifted", name, d)
		}
	}
}

// hijackRecorder is a ResponseWriter that can be hijacked.
type hijackRecorder struct {
	*deadlineRecorder
	conn net.Conn
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

// TestStreamWriterPassesWritersThrough: Hijack, Flush and ReadFrom reach the
// writer beneath, and a hijacked connection's deadlines are left to whoever
// took it.
func TestStreamWriterPassesWritersThrough(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	rec := &hijackRecorder{deadlineRecorder: &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}, conn: server}
	sw := NewStreamWriter(rec, StreamLimits{Idle: time.Minute})
	defer Release(sw)

	if _, err := sw.ReadFrom(strings.NewReader("body")); err != nil || rec.Body.String() != "body" {
		t.Fatalf("ReadFrom wrote %q (%v), want %q", rec.Body.String(), err, "body")
	}
	sw.Flush()
	if !rec.Flushed {
		t.Fatal("Flush did not reach the writer beneath")
	}
	if http.NewResponseController(sw).Flush() != nil {
		t.Fatal("ResponseController could not reach the writer beneath")
	}
	c, _, err := sw.Hijack()
	if err != nil || c != server {
		t.Fatalf("Hijack = %v, %v; want the connection beneath", c, err)
	}
	if len(rec.read)+len(rec.write) != 0 {
		t.Fatal("a hijacked connection's deadlines were touched")
	}

	plain := NewStreamWriter(httptest.NewRecorder(), StreamLimits{})
	defer Release(plain)
	if _, _, err := plain.Hijack(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("Hijack on a writer that cannot = %v, want http.ErrNotSupported", err)
	}
}
