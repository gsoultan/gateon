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

// Telemetry returns a middleware that starts an OpenTelemetry span for each
// request when a collector is configured (telemetry.TracingEnabled), recording
// basic HTTP attributes and making the span available in the context.
//
// Without a collector it starts none. It used to start one regardless, and
// cmd/gateon installed a recording provider even with no endpoint, so every
// request on a default install paid for a span -- the name and five attribute
// strings built up front, the span itself, a request copy for its context, a
// second request id -- that nothing ever read. The reputation and
// recommendation lookups at the end exist only to annotate the span, so they
// go with it.
func Telemetry(serviceName string) Middleware {
	tracer := otel.Tracer(serviceName)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rs := request.GetRequestState(r)
			if rs != nil && rs.TEntrypoint == 0 {
				rs.TEntrypoint = time.Now().UnixNano()
			}
			if !telemetry.TracingEnabled() {
				next.ServeHTTP(w, r)
				return
			}
			serveTraced(tracer, next, w, r, rs)
		})
	}
}

// serveTraced serves r inside a span.
func serveTraced(tracer trace.Tracer, next http.Handler, w http.ResponseWriter, r *http.Request, rs *RequestState) {
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

	// The trace id is the request id, so a stored trace and its span share
	// one. The entrypoint's id stands when the span has none.
	if rs != nil {
		if tid := span.SpanContext().TraceID(); tid.IsValid() {
			rs.RequestID = tid.String()
		} else if rs.RequestID == "" {
			rs.RequestID = request.GenerateID()
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

	recordSpanOutcome(span, sw, r, rs)
}

// recordSpanOutcome adds what the response and the request's security
// verdicts say to the span once next has served.
func recordSpanOutcome(span trace.Span, sw *StatusResponseWriter, r *http.Request, rs *RequestState) {
	span.SetAttributes(
		attribute.Int("http.status_code", sw.Status),
		attribute.Int64("http.response_size", sw.BytesWritten),
	)
	if sw.Status >= 400 {
		span.SetStatus(1, "error")
	}
	if rs == nil {
		return
	}
	// A recommendation captured during the request travels with the span.
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
	span.SetAttributes(attribute.Float64("security.trust_score", telemetry.GetReputation(repID)))
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
