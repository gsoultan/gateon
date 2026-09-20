// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"fmt"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// spanLogger lived in otel.go, which is not moving, and was used only by cors.go
// and grpcweb.go, which are. Nothing in otel.go referenced it -- the file merely
// hosted it. It adds "cors_debug" span events and turns rs/cors's failure
// messages into operator recommendations, so it belongs with the CORS code it
// serves rather than with tracing in general.

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
