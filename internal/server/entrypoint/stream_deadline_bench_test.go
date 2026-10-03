// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// benchWriter is a ResponseWriter that, like net/http's, takes deadlines, and
// otherwise discards what it is given.
type benchWriter struct{ h http.Header }

func (w *benchWriter) Header() http.Header              { return w.h }
func (w *benchWriter) Write(b []byte) (int, error)      { return len(b), nil }
func (w *benchWriter) WriteHeader(int)                  {}
func (w *benchWriter) SetReadDeadline(time.Time) error  { return nil }
func (w *benchWriter) SetWriteDeadline(time.Time) error { return nil }

// BenchmarkDynamicTimeouts is the per-request cost of an entrypoint's
// deadlines: what ADR 0042 changed on every request. It uses nothing that
// changed, so it runs against the tree before the change as well.
func BenchmarkDynamicTimeouts(b *testing.B) {
	ep := &gateonv1.EntryPoint{Id: "bench", ReadTimeoutMs: 15000, WriteTimeoutMs: 15000}
	body := []byte("ok")
	h := dynamicTimeouts(ep, &Deps{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := &benchWriter{h: http.Header{"Content-Type": {"text/plain"}}}
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, req)
	}
}
