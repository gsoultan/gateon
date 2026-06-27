package middleware

import (
	"net/http"
	"net/http/httptest"
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

func benchDriveChain(b *testing.B, h http.Handler) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/widgets?id=42", nil)
			req.RemoteAddr = "203.0.113.7:54321"
			w := httptest.NewRecorder()
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
// which skips the per-request header marshal and JA3/JA4 resolution. The
// allocs/op delta versus TraceAll is the cost P1.2 makes optional.
// (GATEON_PER_IP_METRICS is read once at package init, so it is configured via
// the environment when running this benchmark, not toggled per sub-benchmark.)
func BenchmarkInfraChain_TraceOff(b *testing.B) {
	b.Setenv("GATEON_ACCESS_LOG_SAMPLE_RATE", "0") // isolate the Metrics path from log I/O
	b.Setenv("GATEON_TRACE_SAMPLE_RATE", "0")
	benchDriveChain(b, benchInfraChain())
}
