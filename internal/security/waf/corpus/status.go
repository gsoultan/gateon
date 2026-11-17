// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package corpus

import (
	"bufio"
	"net"
	"net/http"
)

// StatusWriter notes the status a response was answered with and changes
// nothing else about it. It exists only around a sampled request, which is
// kept or not on whether the origin accepted it.
type StatusWriter struct {
	http.ResponseWriter
	status int
}

// Watch wraps w.
func Watch(w http.ResponseWriter) *StatusWriter { return &StatusWriter{ResponseWriter: w} }

// Status is the status the response was answered with: 200 when the handler
// wrote a body without one, and 0 when it wrote nothing at all.
func (s *StatusWriter) Status() int { return s.status }

func (s *StatusWriter) WriteHeader(code int) {
	// An informational response is not the answer.
	if s.status == 0 && code >= http.StatusOK {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *StatusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach what this wraps.
func (s *StatusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush keeps streaming responses streaming.
func (s *StatusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack hands the connection over as the wrapped writer would.
func (s *StatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}
