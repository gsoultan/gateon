// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
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
// wrote decides nothing.
//
// A WebSocket is not lifted here: its upgrade hijacks the connection, and the
// tunnel that follows bounds itself (Clock).
type StreamWriter struct {
	http.ResponseWriter
	limits    StreamLimits
	decided   bool // a final status has been written, or the connection hijacked
	streaming bool
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
		return rf.ReadFrom(src)
	}
	return io.Copy(writerOnly{s}, src)
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
// text/event-stream is a stream from here on.
func (s *StreamWriter) decide(code int) {
	s.decided = true
	if code != http.StatusOK || !IsEventStream(s.Header().Get("Content-Type")) {
		return
	}
	s.streaming = true
	now := time.Now()
	s.start = now
	s.move(now)
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
