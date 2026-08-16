// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/url"
	"testing"
)

// benchInfraChain builds the infrastructure middleware chain that every proxied
// request passes through (Recovery → AccessLog → Metrics) wrapping a trivial
// backend. This is the hot path that P1 trims: the Metrics middleware's
// per-request trace marshal (gated by GATEON_TRACE_SAMPLE_RATE) and the
// per-client-IP Prometheus series (gated by GATEON_PER_IP_METRICS).
func benchInfraChain() http.Handler {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	chain := Chain(Recovery(), AccessLog("bench-route"), Metrics("bench-route"))
	return chain(backend)
}

// This benchmark used to build its request with httptest.NewRequest and its
// response with httptest.NewRecorder, both inside the timed loop. Both are
// expensive in a way the chain is not responsible for: httptest.NewRequest
// constructs its *http.Request by parsing a raw HTTP/1.1 wire message, which
// allocates a 4KB bufio.Reader every call. A memory profile of the old
// benchmark attributed 94% of all allocated bytes to
// httptest.NewRequestWithContext — 76% to bufio.NewReaderSize alone — against
// roughly 3% for every piece of Gateon code in the chain combined.
//
// So the reported ~5.5KB/op was very nearly a measurement of the harness. Real
// servers do parse a request per request, but the read buffer is per
// *connection* and reused across keep-alives, so paying it per iteration
// overstated the chain by about an order of magnitude and would have sent any
// optimisation work chasing net/http's allocations rather than ours.
//
// Each iteration still gets its own Request, URL and header maps, so iterations
// remain independent and nothing is shared across the parallel goroutines. What
// is excluded now is only wire parsing and response recording.
var (
	benchURL        = mustParseBenchURL("http://localhost/api/v1/widgets?id=42")
	benchRequestURI = benchURL.RequestURI()
)

func mustParseBenchURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// benchResponseWriter discards everything. httptest.NewRecorder buffers the
// body and clones headers, neither of which the chain's cost depends on.
type benchResponseWriter struct {
	header http.Header
	status int
}

func (w *benchResponseWriter) Header() http.Header         { return w.header }
func (w *benchResponseWriter) WriteHeader(status int)      { w.status = status }
func (w *benchResponseWriter) Write(p []byte) (int, error) { return len(p), nil }

func benchDriveChain(b *testing.B, h http.Handler) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Copied per iteration: a middleware that rewrites the path would
			// otherwise mutate state shared across the parallel goroutines.
			reqURL := *benchURL
			req := &http.Request{
				Method:     http.MethodGet,
				URL:        &reqURL,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     make(http.Header, 4),
				Host:       benchURL.Host,
				RemoteAddr: "203.0.113.7:54321",
				RequestURI: benchRequestURI,
				Body:       http.NoBody,
			}
			w := &benchResponseWriter{header: make(http.Header, 4)}
			h.ServeHTTP(w, req)
		}
	})
}

// BenchmarkInfraChain_TraceAll measures the chain with trace recording on
// (default behavior): every request marshals request+response headers to JSON.
func BenchmarkInfraChain_TraceAll(b *testing.B) {
	b.Setenv("GATEON_ACCESS_LOG_SAMPLE_RATE", "0") // isolate the Metrics path from log I/O
	b.Setenv("GATEON_TRACE_SAMPLE_RATE", "1")
	benchDriveChain(b, benchInfraChain())
}

// BenchmarkInfraChain_TraceOff measures the chain with trace recording disabled,
// which skips the per-request header marshal and JA4+ resolution. The
// allocs/op delta versus TraceAll is the cost P1.2 makes optional.
// (GATEON_PER_IP_METRICS is read once at package init, so it is configured via
// the environment when running this benchmark, not toggled per sub-benchmark.)
func BenchmarkInfraChain_TraceOff(b *testing.B) {
	b.Setenv("GATEON_ACCESS_LOG_SAMPLE_RATE", "0") // isolate the Metrics path from log I/O
	b.Setenv("GATEON_TRACE_SAMPLE_RATE", "0")
	benchDriveChain(b, benchInfraChain())
}
