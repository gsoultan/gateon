// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// failingWriter is a ResponseWriter whose writes fail with err.
type failingWriter struct {
	*httptest.ResponseRecorder
	err error
}

func (f *failingWriter) Write([]byte) (int, error) { return 0, f.err }

func (f *failingWriter) ReadFrom(io.Reader) (int64, error) { return 0, f.err }

var errDeadline = errors.New("deadline exceeded")

// TestAFailedWriteIsACut: DP-N4. A write the client did not receive leaves the
// response incomplete, whichever way the handler wrote it.
func TestAFailedWriteIsACut(t *testing.T) {
	for name, write := range map[string]func(http.ResponseWriter){
		"Write":    func(w http.ResponseWriter) { _, _ = w.Write([]byte("x")) },
		"ReadFrom": func(w http.ResponseWriter) { _, _ = io.Copy(w, strings.NewReader("x")) },
	} {
		t.Run(name, func(t *testing.T) {
			sw := NewStreamWriter(&failingWriter{httptest.NewRecorder(), errDeadline}, StreamLimits{})
			defer Release(sw)
			write(sw)
			if !sw.Cut() {
				t.Error("a write that failed did not mark the response cut")
			}
		})
	}
}

// TestALostBodyThatWasNotOwedIsNotACut: a body on a 204 or 304, and a write
// after a hijack, lose nothing the client was owed. Aborting those would turn
// a complete answer into a reset.
func TestALostBodyThatWasNotOwedIsNotACut(t *testing.T) {
	for _, err := range []error{http.ErrBodyNotAllowed, http.ErrHijacked, nil} {
		sw := NewStreamWriter(&failingWriter{httptest.NewRecorder(), err}, StreamLimits{})
		_, _ = sw.Write([]byte("x"))
		if sw.Cut() {
			t.Errorf("a write failing with %v marked the response cut", err)
		}
		Release(sw)
	}
}

// TestACutResponseIsAborted: the listener's handler ends a cut response with
// http.ErrAbortHandler -- the one signal every server (HTTP/1, HTTP/2, quic-go)
// takes to mean "do not finish this" -- and a whole one normally.
func TestACutResponseIsAborted(t *testing.T) {
	timeouts := RequestTimeouts{Read: time.Second, Write: time.Second}
	serve := func(err error) (recovered any) {
		defer func() { recovered = recover() }()
		h := timeouts.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("x"))
		}), StreamLimits{})
		h.ServeHTTP(&failingWriter{httptest.NewRecorder(), err}, httptest.NewRequest(http.MethodGet, "/", nil))
		return nil
	}
	if got := serve(errDeadline); got != http.ErrAbortHandler { //nolint:errorlint // recover() value
		t.Errorf("a cut response ended with %v, want a panic with http.ErrAbortHandler", got)
	}
	if got := serve(nil); got != nil {
		t.Errorf("a whole response panicked with %v", got)
	}
}
