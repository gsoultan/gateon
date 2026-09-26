// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestSpanURLCarriesNoQueryCredentials sends a request with a token in its
// query through the tracing middleware and reads the exported span. The
// http.url attribute carried the full URL, so every OTLP collector the gateway
// was pointed at received the API keys and bearer tokens clients put in query
// strings, unmasked.
func TestSpanURLCarriesNoQueryCredentials(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	const secret = "tok-5f2c9d1e"
	h := Telemetry("otel-url-test")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet,
		"http://api.example.com/v1/items?access_token="+secret+"&page=2", nil))

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}
	for _, kv := range spans[0].Attributes() {
		if string(kv.Key) != "http.url" {
			continue
		}
		got := kv.Value.AsString()
		if strings.Contains(got, secret) {
			t.Fatalf("http.url exported the token: %q", got)
		}
		if !strings.Contains(got, "/v1/items") || !strings.Contains(got, "page=") {
			t.Fatalf("http.url lost the path or the query keys: %q", got)
		}
		return
	}
	t.Fatal("the span carried no http.url attribute")
}
