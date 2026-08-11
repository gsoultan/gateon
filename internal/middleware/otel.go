// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
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
					attribute.String("http.url", r.URL.String()),
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
					repID = request.GetClientIP(r, true)
				}
				reputation := telemetry.GetReputation(repID)
				span.SetAttributes(attribute.Float64("security.trust_score", reputation))
			}
		})
	}
}

type spanLogger struct {
	span trace.Span
	rs   *request.RequestState
}

func (l *spanLogger) Printf(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	l.span.AddEvent("cors_debug", trace.WithAttributes(
		attribute.String("message", msg),
	))

	recommendation := ""
	// Smart Recommendations based on common CORS failure messages (case-insensitive)
	lowerMsg := strings.ToLower(msg)
	if strings.Contains(lowerMsg, "origin") && strings.Contains(lowerMsg, "not allowed") {
		recommendation = "The request origin is not permitted. Update the CORS 'Allowed Origins' to include it."
		l.span.SetAttributes(
			attribute.Bool("cors.blocked", true),
			attribute.String("security.recommendation", recommendation),
		)
	} else if strings.Contains(lowerMsg, "method") && strings.Contains(lowerMsg, "not allowed") {
		recommendation = "The HTTP method is not permitted for CORS. Update 'Allowed Methods' in your CORS configuration."
		l.span.SetAttributes(
			attribute.Bool("cors.blocked", true),
			attribute.String("security.recommendation", recommendation),
		)
	} else if strings.Contains(lowerMsg, "header") && strings.Contains(lowerMsg, "not allowed") {
		recommendation = "The request includes headers not permitted by CORS. Update 'Allowed Headers' in your configuration."
		l.span.SetAttributes(
			attribute.Bool("cors.blocked", true),
			attribute.String("security.recommendation", recommendation),
		)
	}

	if recommendation != "" && l.rs != nil {
		l.rs.Recommendation = recommendation
		logger.L.LogDebug("Captured CORS recommendation", "recommendation", recommendation, "request_id", l.rs.RequestID)
	}
}
