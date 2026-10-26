// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// A gateway with no OTLP endpoint configured still paid for a span on every
// request: InitTracer installed an SDK provider that sampled everything and
// exported nothing, at 3.6 µs and 2.4 KB per request on a 2-core budget. The
// middleware now starts a span only once InitTracer has been told where to
// send it, whatever provider is installed globally.
func TestTelemetryStartsNoSpanUntilTracingIsEnabled(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	telemetry.SetTracingEnabled(false)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	h := Telemetry("otel-disabled-test")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1/items", nil)
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{}))

	w := httptest.NewRecorder()
	if n := testing.AllocsPerRun(100, func() { h.ServeHTTP(w, req) }); n > 0 {
		t.Fatalf("tracing is disabled yet the middleware allocated %v times per request", n)
	}
	if spans := rec.Ended(); len(spans) != 0 {
		t.Fatalf("recorded %d spans with tracing disabled, want 0", len(spans))
	}
}
