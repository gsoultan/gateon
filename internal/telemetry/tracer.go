// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// tracingEnabled is whether spans go anywhere: set by InitTracer when an OTLP
// endpoint is configured, read by the request path to decide whether to start
// one at all.
var tracingEnabled atomic.Bool

// TracingEnabled reports whether a span started for a request reaches a
// collector. Without an OTLP endpoint there is no provider, and the request
// path starts no span: with one installed and nothing reading it, every
// request paid a recording span -- 3.6µs, 2.4 KB and 12 allocations, more than
// the rest of the infrastructure chain -- to produce an id the entrypoint had
// already generated.
func TracingEnabled() bool {
	return tracingEnabled.Load()
}

// SetTracingEnabled is for a test that installs a tracer provider of its own
// and wants the request path to start spans for it; InitTracer sets it for
// the gateway.
func SetTracingEnabled(enabled bool) {
	tracingEnabled.Store(enabled)
}

// InitTracer configures an OTLP exporter and its trace provider when
// OTEL_EXPORTER_OTLP_ENDPOINT names a collector. Without one it installs
// nothing and the global provider stays the no-op: request ids come from the
// entrypoint (request.GenerateID), not from a span.
func InitTracer(serviceName string) (func(context.Context) error, error) {
	ctx := context.Background()

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		tracingEnabled.Store(false)
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	traceExporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	otel.SetTracerProvider(tracerProvider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	tracingEnabled.Store(true)

	return tracerProvider.Shutdown, nil
}
