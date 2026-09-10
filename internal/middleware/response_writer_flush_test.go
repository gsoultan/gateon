// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every middleware that wraps http.ResponseWriter has to re-expose the optional
// interfaces, because embedding promotes only Header, Write and WriteHeader --
// Flush and Hijack are not part of http.ResponseWriter and are lost the moment
// a wrapper goes on.
//
// The honeypot and deception wrappers implement Hijack and not Flush. That
// asymmetry is not random: both carry a comment reasoning about WebSocket
// upgrades, so someone thought about Hijack and nobody thought about SSE. The
// effect is that a Server-Sent Events response behind either middleware never
// reaches the client until the upstream closes the stream -- the data is
// correct and arrives all at once, at the end, which reads as a dead feed
// rather than as a middleware bug.
//
// Gateon advertises SSE proxying (doc/websockets-sse.md), and the response path
// has been bitten by exactly this once before: the DLP content-type gate reached
// a branch that committed the header without marking the response flushed, and
// Flush stopped reaching the client.
//
// These wrap a Flusher and assert the wrapper is still one.

type flushCounter struct {
	http.ResponseWriter
	flushes int
}

func (f *flushCounter) Flush() { f.flushes++ }

func TestResponseWrappersPreserveFlush(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap func(http.ResponseWriter) http.ResponseWriter
	}{
		{"deception", func(w http.ResponseWriter) http.ResponseWriter {
			return &deceptionResponseWriter{ResponseWriter: w}
		}},
		{"honeypot breadcrumb", func(w http.ResponseWriter) http.ResponseWriter {
			return &breadcrumbWriter{ResponseWriter: w, request: httptest.NewRequest(http.MethodGet, "/", nil)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &flushCounter{ResponseWriter: httptest.NewRecorder()}
			wrapped := tc.wrap(base)

			f, ok := wrapped.(http.Flusher)
			if !ok {
				t.Fatalf("%s wrapper is not an http.Flusher, so SSE behind it never "+
					"reaches the client until the upstream closes", tc.name)
			}
			f.Flush()
			if base.flushes != 1 {
				t.Fatalf("%s: Flush did not reach the underlying writer (%d flushes)", tc.name, base.flushes)
			}
		})
	}
}

// A wrapper over a writer that cannot flush must not panic; it just does
// nothing, which is what the WAF wrapper already does.
func TestResponseWrappersFlushSafelyWithoutAFlusher(t *testing.T) {
	type plain struct{ http.ResponseWriter }
	base := plain{httptest.NewRecorder()}

	for name, w := range map[string]http.ResponseWriter{
		"deception":           &deceptionResponseWriter{ResponseWriter: base},
		"honeypot breadcrumb": &breadcrumbWriter{ResponseWriter: base, request: httptest.NewRequest(http.MethodGet, "/", nil)},
	} {
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // must not panic
		} else {
			t.Errorf("%s should still expose Flush", name)
		}
	}
}
