package middleware

import (
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
)

type ContextKey string

const (
	EntryPointIDContextKey ContextKey = "entrypoint_id"
	RouteNameContextKey    ContextKey = "route_name"
	IsManagementContextKey ContextKey = "is_management"
)

// GetRouteName returns the route ID from the request context, or empty if not set.
func GetRouteName(r *http.Request) string {
	if val, ok := r.Context().Value(RouteNameContextKey).(string); ok {
		return val
	}
	return ""
}

// IsInternalPath returns true if the given path belongs to Gateon's internal API,
// monitoring, or health-check system.
func IsInternalPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/metrics" || path == "/healthz" || path == "/readyz"
}

// ShouldSkipMetrics determines if Prometheus metrics recording should be skipped
// for a given request. It skips metrics for the management entrypoint and internal
// paths, unless it's a dedicated proxy route (non-gateon prefix).
func ShouldSkipMetrics(r *http.Request) bool {
	isMgmt, _ := r.Context().Value(IsManagementContextKey).(bool)
	if isMgmt {
		return true
	}

	routeID := GetRouteName(r)

	// For infrastructure-level metrics (entrypoints starting with "gateon-"),
	// skip recording for any internal paths to isolate proxy metrics.
	if strings.HasPrefix(routeID, "gateon-") && IsInternalPath(r.URL.Path) {
		return true
	}

	return false
}

// Middleware defines a function that wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Recovery returns a middleware that recovers from panics, logs the stack, and returns 500.
// Prevents a single panicking handler from crashing the server.
func Recovery() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.L.Error().
						Interface("panic", err).
						Str("path", r.URL.Path).
						Str("method", r.Method).
						Str("stack", string(debug.Stack())).
						Msg("handler panic recovered")
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders returns a middleware that adds standard security headers to all responses.
func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			next.ServeHTTP(w, r)
		})
	}
}

// Chain composes multiple middlewares into a single middleware.
// The middlewares are executed in the order they are provided.
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}
