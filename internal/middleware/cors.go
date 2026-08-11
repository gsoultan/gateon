// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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
//
// Credentials are deliberately NOT allowed here. Reflecting an arbitrary Origin
// and setting Access-Control-Allow-Credentials: true is the one CORS
// combination that is always unsafe — it lets any page on the internet issue
// credentialed requests to every backend behind the gateway and read the
// replies. A route that genuinely needs credentials must declare an explicit
// origin allowlist through CORS(CORSConfig), where the operator names the
// origins being trusted.
func BypassCORS() Middleware {
	c := cors.New(cors.Options{
		AllowOriginFunc:  func(origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: false,
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

// GlobalCORS returns a middleware that handles CORS preflight requests
// permissively for the entire entrypoint. It ensures that even early
// security blocks (like IP shunning) include the necessary CORS headers
// to avoid confusing browser-level errors. Unlike BypassCORS, it does
// not set CORSHandledContextKey, allowing route-specific CORS middlewares
// to override its settings for the actual request.
//
// This runs on every HTTP entrypoint, so it is the widest-reach CORS policy in
// the gateway and must stay credential-free. Its job is to make browser errors
// legible on paths that never reach a route — not to grant cross-origin access
// to authenticated data. Reflecting an arbitrary Origin with
// Access-Control-Allow-Credentials: true would do exactly that, for every
// backend at once, and browsers honour the reflected form even though they
// reject the equivalent `*`. Credentials belong to CORS(CORSConfig), where an
// operator has named the origins.
func GlobalCORS() Middleware {
	c := cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool { return true },
		AllowedMethods:  []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
		AllowedHeaders:  []string{"*"},
		ExposedHeaders: []string{
			"Grpc-Status", "Grpc-Message", "Grpc-Encoding",
			"Grpc-Accept-Encoding", "X-Grpc-Web", "X-Accept-Content-Transfer-Encoding",
			"X-Accept-Response-Streaming", "Authorization", "Content-Type",
		},
		AllowCredentials: false,
		MaxAge:           86400,
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// For preflights, handle them here permissively and return immediately.
			if IsCorsPreflight(r) {
				c.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(w, r)
				return
			}

			// For actual requests, apply permissive headers but let downstream handlers override.
			c.Handler(next).ServeHTTP(w, r)
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

// corsRouteID resolves the identifier of the route that handled the request.
// The matched route's ID is preferred because it is what the remediation API
// looks up; RouteName is only a display label and may hold the entrypoint
// fallback when the route has no name.
func corsRouteID(rs *request.RequestState) string {
	if rs == nil {
		return ""
	}
	if route, ok := rs.MatchedRoute.(interface{ GetId() string }); ok && route.GetId() != "" {
		return route.GetId()
	}
	return rs.RouteName
}

func reportCORSViolation(r *http.Request, origin string, cfg CORSConfig) {
	routeID := corsRouteID(request.GetRequestState(r))

	threat := telemetry.SecurityThreat{
		ID:             uuid.New().String(),
		Type:           "cors_violation",
		Category:       "security",
		Severity:       severityMedium,
		SourceIP:       request.GetClientIP(r, false),
		RequestURI:     r.RequestURI,
		RouteID:        routeID,
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
