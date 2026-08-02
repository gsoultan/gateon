// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/alerting"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/rs/cors"
	"go.opentelemetry.io/otel/trace"
)

// CORSConfig defines the configuration for the CORS middleware.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
	Debug            bool
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing (CORS).
func CORS(cfg CORSConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(CORSHandledContextKey) != nil {
				next.ServeHTTP(w, r)
				return
			}

			span := trace.SpanFromContext(r.Context())
			opts := cors.Options{
				AllowedOrigins:   cfg.AllowedOrigins,
				AllowedMethods:   cfg.AllowedMethods,
				AllowedHeaders:   cfg.AllowedHeaders,
				ExposedHeaders:   cfg.ExposedHeaders,
				AllowCredentials: cfg.AllowCredentials,
				MaxAge:           cfg.MaxAge,
				Debug:            cfg.Debug || span.IsRecording(),
			}

			if span.IsRecording() {
				opts.Logger = &spanLogger{span: span, rs: request.GetRequestState(r)}
			}

			c := cors.New(opts)

			// Detect invalid CORS request
			origin := r.Header.Get("Origin")
			if origin != "" && !isOriginAllowed(origin, cfg.AllowedOrigins) {
				reportCORSViolation(r, origin, cfg)
			}

			// Mark as handled for downstream middlewares
			wrappedNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(context.WithValue(r.Context(), CORSHandledContextKey, true))
				next.ServeHTTP(w, r)
			})

			c.Handler(wrappedNext).ServeHTTP(w, r)
		})
	}
}

// BypassCORS returns a middleware that automatically handles CORS preflight requests
// by allowing all origins, methods, and headers. It is intended to be used as a
// fallback when no specific CORS middleware is configured, restoring v1.5.0 behavior.
func BypassCORS() Middleware {
	c := cors.New(cors.Options{
		AllowOriginFunc:  func(origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400,
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(CORSHandledContextKey) != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Mark as handled for downstream middlewares
			wrappedNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(context.WithValue(r.Context(), CORSHandledContextKey, true))
				next.ServeHTTP(w, r)
			})

			c.Handler(wrappedNext).ServeHTTP(w, r)
		})
	}
}

func isOriginAllowed(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if a == "*" || strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}

func reportCORSViolation(r *http.Request, origin string, cfg CORSConfig) {
	rs := request.GetRequestState(r)
	routeName := ""
	if rs != nil {
		routeName = rs.RouteName
	}

	threat := telemetry.SecurityThreat{
		ID:             uuid.New().String(),
		Type:           "cors_violation",
		Category:       "security",
		Severity:       "medium",
		SourceIP:       request.GetClientIP(r, false),
		RequestURI:     r.RequestURI,
		RouteID:        routeName,
		Details:        fmt.Sprintf("Invalid CORS request from origin: %s. Allowed origins: %v", origin, cfg.AllowedOrigins),
		Time:           time.Now(),
		UserAgent:      r.UserAgent(),
		Method:         r.Method,
		Recommendation: "Verify if this origin should be allowed in the CORS configuration for this route.",
	}

	threat = telemetry.RecordSecurityThreatWithJA4(r, threat)
	telemetry.RecordSecurityThreat(threat)
	alerting.HandleThreat(&threat)
}
