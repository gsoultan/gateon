// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/request"
)

// eventStreamType is the media type of a server-sent-event response.
const eventStreamType = "text/event-stream"

// IsEventStream reports whether contentType names a server-sent-event
// response: text/event-stream, in any case, with or without parameters.
func IsEventStream(contentType string) bool {
	ct := strings.TrimLeft(contentType, " \t")
	if len(ct) < len(eventStreamType) || !strings.EqualFold(ct[:len(eventStreamType)], eventStreamType) {
		return false
	}
	rest := ct[len(eventStreamType):]
	return rest == "" || rest[0] == ';' || rest[0] == ' ' || rest[0] == '\t'
}

// StreamWriter is the ResponseWriter a listener hands its handler. It does
// nothing until the response's status is written; then, if the response is a
// 200 whose Content-Type is text/event-stream, it replaces the request's read
// and write deadlines with the stream's bounds, and moves them on as the
// stream writes. Any other response keeps the deadlines it was given.
//
// What decides is the answer, not the request: the server -- a backend, or a
// management handler -- has to have chosen to stream. A header the client
// wrote decides nothing. The route the request matched may decide instead
// (SetStreamMode): its operator said it always or never streams (ADR 0064).
//
// A WebSocket is not lifted here: its upgrade hijacks the connection, and the
// tunnel that follows bounds itself (Clock).
type StreamWriter struct {
	http.ResponseWriter
	limits    StreamLimits
	mode      request.StreamMode // the matched route's say, StreamAuto when it has none
	decided   bool               // a final status has been written, or the connection hijacked
	streaming bool
	cut       bool      // a write to the client failed: the response is incomplete
	start     time.Time // when the stream began
	moved     time.Time // when its deadlines were last moved
}

var streamWriterPool = sync.Pool{New: func() any { return new(StreamWriter) }}

// NewStreamWriter returns a pooled StreamWriter around w. The caller returns
// it with Release once the handler it was given to has returned.
func NewStreamWriter(w http.ResponseWriter, limits StreamLimits) *StreamWriter {
	s, ok := streamWriterPool.Get().(*StreamWriter)
	if !ok {
		s = new(StreamWriter)
	}
	*s = StreamWriter{ResponseWriter: w, limits: limits}
	return s
}

// Release returns s to the pool. s must not be used afterwards.
func Release(s *StreamWriter) {
	*s = StreamWriter{}
	streamWriterPool.Put(s)
}

// Streaming reports whether the response was lifted as a stream.
func (s *StreamWriter) Streaming() bool { return s.streaming }

// SetStreamMode is the matched route's say in the decision (ADR 0064). It has
// none once the decision is made: a response already begun keeps its bounds.
func (s *StreamWriter) SetStreamMode(m request.StreamMode) {
	if !s.decided {
		s.mode = m
	}
}

// WriteHeader decides, at the first final status, whether the response is a
// stream. An informational status (1xx) is not final and decides nothing.
func (s *StreamWriter) WriteHeader(code int) {
	if !s.decided && code >= http.StatusOK {
		s.decide(code)
	}
	s.ResponseWriter.WriteHeader(code)
}

// Write writes b, deciding first when no status has been written -- net/http
// sends 200 then -- and, on a stream, moves its deadlines on.
func (s *StreamWriter) Write(b []byte) (int, error) {
	if !s.decided {
		s.decide(http.StatusOK)
	}
	n, err := s.ResponseWriter.Write(b)
	if s.streaming && n > 0 {
		s.touch()
	}
	if err != nil {
		s.noteFailure(err)
	}
	return n, err
}

// ReadFrom keeps net/http's own ReadFrom -- a pooled copy, or sendfile(2) --
// within reach of a handler that copies into the response, except on a
// stream, whose deadlines have to move as it writes.
func (s *StreamWriter) ReadFrom(src io.Reader) (int64, error) {
	if !s.decided {
		s.decide(http.StatusOK)
	}
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok && !s.streaming {
		n, err := rf.ReadFrom(src)
		if err != nil {
			s.noteFailure(err)
		}
		return n, err
	}
	return io.Copy(writerOnly{s}, src)
}

// noteFailure records that the response did not reach the client whole.
// ErrBodyNotAllowed (a body on a 204 or 304) and ErrHijacked lose nothing the
// client was owed, so they are not a cut.
func (s *StreamWriter) noteFailure(err error) {
	if !errors.Is(err, http.ErrBodyNotAllowed) && !errors.Is(err, http.ErrHijacked) {
		s.cut = true
	}
}

// Cut reports whether a write to the client failed -- a deadline passed, the
// stream was reset -- so the response the handler produced is incomplete.
func (s *StreamWriter) Cut() bool { return s.cut }

// AbortIfCut ends a cut response as an abort: it panics with
// http.ErrAbortHandler, which every server takes to mean "do not finish this
// response". Without it, a handler that returns normally after a failed write
// -- httputil.ReverseProxy does, when the request carries no
// http.ServerContextKey -- leaves HTTP/3 to end the stream cleanly, and a
// streamed response with no Content-Length then reads as complete (DP-N4).
// HTTP/1 closes the connection and HTTP/2 resets the stream, as they already
// did once the deadline passed. Called after the handler has returned.
func (s *StreamWriter) AbortIfCut() {
	if s.cut {
		panic(http.ErrAbortHandler)
	}
}

// writerOnly hides every method of a writer but Write, so io.Copy cannot hand
// the copy back to the ReadFrom that called it.
type writerOnly struct{ io.Writer }

// Flush sends whatever is buffered to the client.
func (s *StreamWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack hands the connection to the handler, which owns its deadlines from
// then on; nothing here touches them again.
func (s *StreamWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	s.decided = true
	return h.Hijack()
}

// Unwrap lets http.ResponseController reach the writer beneath.
func (s *StreamWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// decide makes the one decision: a 200 whose Content-Type is
// text/event-stream and that declares no length is a stream from here on,
// unless the route said otherwise (isStream).
//
// The length is what tells an event stream from an object that only carries
// its type (DP-N7). An app that stores uploads under the type the uploader
// chose answers one with text/event-stream, and on the type alone a client
// reading nothing held it -- a goroutine, a backend connection -- for the
// stream lifetime. An event stream has no end to declare, so it never sends
// Content-Length; a stored object almost always does. The request's Accept
// still decides nothing (ADR 0042): the client asking for the lift is the
// party the deadline is there to bound.
func (s *StreamWriter) decide(code int) {
	s.decided = true
	if !s.isStream(code) {
		return
	}
	s.streaming = true
	now := time.Now()
	s.start = now
	s.move(now)
}

// isStream is the decision. A route that never streams keeps the
// entrypoint's deadlines on every response. A route that always streams lifts
// every response -- but only to bounds that exist: with both stream bounds
// disabled a lifted response would have no deadline at all, and a per-route
// switch must not be how a response gets none, so it keeps the entrypoint's.
func (s *StreamWriter) isStream(code int) bool {
	switch s.mode {
	case request.StreamNever:
		return false
	case request.StreamAlways:
		return s.limits.Idle > 0 || s.limits.MaxLifetime > 0
	}
	h := s.Header()
	return code == http.StatusOK && IsEventStream(h.Get("Content-Type")) && h.Get("Content-Length") == ""
}

// touch moves a stream's deadlines on after it wrote. Moving them costs
// something on HTTP/2 -- a message to the connection's goroutine -- so a
// stream writing many small events moves them at most once per sixteenth of
// its idle timeout: the idle bound it actually gets lies between fifteen
// sixteenths of the configured one and all of it.
func (s *StreamWriter) touch() {
	if s.limits.Idle <= 0 {
		return // only the lifetime bounds it, and that was set when it began
	}
	now := time.Now()
	if now.Sub(s.moved) < s.limits.Idle/16 {
		return
	}
	s.move(now)
}

// move sets both deadlines to when the stream ends if nothing more moves.
// Both, because on HTTP/1 the read deadline is what ends a quiet stream -- the
// server's background read times out and cancels the request -- and on HTTP/2
// the write deadline is, by resetting the stream.
func (s *StreamWriter) move(now time.Time) {
	end := s.limits.endAt(s.start, now)
	rc := http.NewResponseController(s.ResponseWriter)
	_ = rc.SetReadDeadline(end)
	_ = rc.SetWriteDeadline(end)
	s.moved = now
}
