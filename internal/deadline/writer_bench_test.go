// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"net/http"
	"testing"
)

// discardWriter is a ResponseWriter that keeps nothing, so the benchmark
// measures the StreamWriter and not a recorder.
type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(int)             {}

// BenchmarkStreamWriterResponse is what every response on every listener pays
// for the StreamWriter: one pooled writer, the stream decision at the status,
// and a few writes.
func BenchmarkStreamWriterResponse(b *testing.B) {
	w := &discardWriter{h: http.Header{"Content-Type": {"application/json"}, "Content-Length": {"64"}}}
	body := make([]byte, 16)
	b.ReportAllocs()
	for b.Loop() {
		sw := NewStreamWriter(w, StreamLimits{})
		sw.WriteHeader(http.StatusOK)
		for range 4 {
			_, _ = sw.Write(body)
		}
		Release(sw)
	}
}
