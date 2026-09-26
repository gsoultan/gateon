// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Telemetry returns a middleware that starts an OpenTelemetry span for each request.
// It records basic HTTP attributes and ensures the span is available in the context.
func Telemetry(serviceName string) Middleware {
	tracer := otel.Tracer(serviceName)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := tracer.Start(r.Context(), r.Method+" "+r.URL.Path,
				trace.WithAttributes(
					attribute.String("http.method", r.Method),
					attribute.String("http.url", spanURL(r.URL)),
					attribute.String("http.host", r.Host),
					attribute.String("http.user_agent", r.UserAgent()),
					attribute.String("http.remote_addr", r.RemoteAddr),
				),
				trace.WithSpanKind(trace.SpanKindServer),
			)
			defer span.End()

			// Inject trace ID into request state if available
			rs := request.GetRequestState(r)
			if rs != nil {
				tid := span.SpanContext().TraceID()
				if tid.IsValid() {
					rs.RequestID = tid.String()
				} else {
					// Fallback if the tracer failed to generate a valid ID (e.g. no-op tracer)
					rs.RequestID = request.GenerateID()
				}
				if rs.TEntrypoint == 0 {
					rs.TEntrypoint = time.Now().UnixNano()
				}
			}

			sw, ok := w.(*StatusResponseWriter)
			var pooled bool
			if !ok {
				sw = GetStatusResponseWriter(w)
				pooled = true
			}
			if pooled {
				defer PutStatusResponseWriter(sw)
			}

			next.ServeHTTP(sw, r.WithContext(ctx))

			span.SetAttributes(
				attribute.Int("http.status_code", sw.Status),
				attribute.Int64("http.response_size", sw.BytesWritten),
			)

			if sw.Status >= 400 {
				span.SetStatus(1, "error")
			}

			// If a recommendation was captured during the request, attach it to the span
			if rs != nil {
				rec := rs.Recommendation
				if rec == "" {
					rec = telemetry.GetRecommendation(rs.RequestID)
				}
				if rec != "" {
					span.SetAttributes(attribute.String("security.recommendation", rec))
				}
				repID, _ := rs.Fingerprint.(string)
				if repID == "" {
					repID = request.ClientAddr(r)
				}
				reputation := telemetry.GetReputation(repID)
				span.SetAttributes(attribute.Float64("security.trust_score", reputation))
			}
		})
	}
}

// spanURL is the request URL as a span may carry it. Query values are
// replaced, keys kept: they are where API keys and tokens travel (?token=,
// ?access_token=, ?api_key=), and a span goes to whatever collector
// OTEL_EXPORTER_OTLP_ENDPOINT names, with none of the gateway's secret masking.
// Userinfo is dropped for the same reason.
func spanURL(u *url.URL) string {
	if u.RawQuery == "" && u.User == nil {
		return u.String()
	}
	c := *u
	c.User = nil
	if c.RawQuery != "" {
		pairs := strings.Split(c.RawQuery, "&")
		for i, pair := range pairs {
			if key, _, hasValue := strings.Cut(pair, "="); hasValue {
				pairs[i] = key + "=REDACTED"
			}
		}
		c.RawQuery = strings.Join(pairs, "&")
	}
	return c.String()
}
