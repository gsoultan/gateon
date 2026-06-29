// Package kind holds the cycle-free core primitives of the middleware layer:
// the Middleware type, composition (Chain), panic Recovery, request-context keys,
// path predicates, security-header presets, the pooled StatusResponseWriter, and
// the custom-error-page middleware.
//
// It is a near-leaf package (it imports only the standard library, internal/logger,
// and internal/request — both themselves cycle-free) so that the per-concern
// middleware subpackages (auth, security, traffic, transform) can depend on it
// without creating an import cycle with the parent package middleware
// (ADR-0002, Stage 0).
package kind

import (
	"net/http"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
)

// ContextKey is the type used for values stored in a request's context by the
// middleware layer.
type ContextKey string

const (
	EntryPointIDContextKey ContextKey = "entrypoint_id"
	RouteNameContextKey    ContextKey = "route_name"
	MatchedRouteContextKey ContextKey = "matched_route"
	IsManagementContextKey ContextKey = "is_management"
	DebugInfoContextKey    ContextKey = "debug_info"
	FingerprintContextKey  ContextKey = "fingerprint"
	RequestStateContextKey ContextKey = "request_state"
)

var RequestStatePool = sync.Pool{
	New: func() any {
		return &RequestState{}
	},
}

// RequestState holds mutable request-scoped data to avoid multiple context allocations.
type RequestState struct {
	EntryPointID string
	RouteName    string
	IsManagement bool
	MatchedRoute any // avoids circular dependency with proto
	DebugInfo    *DebugInfo
	RequestID    string
}

// GetRequestState returns the RequestState from the context, or nil if not set.
func GetRequestState(r *http.Request) *RequestState {
	if val, ok := r.Context().Value(RequestStateContextKey).(*RequestState); ok {
		return val
	}
	return nil
}

// DebugInfo captures request/response details for diagnostic tracing.
type DebugInfo struct {
	RequestHeaders  string
	RequestBody     string
	ResponseHeaders string
	ResponseBody    string
}

// GetRouteName returns the route ID from the request context, or empty if not set.
func GetRouteName(r *http.Request) string {
	if rs := GetRequestState(r); rs != nil {
		return rs.RouteName
	}
	if val, ok := r.Context().Value(RouteNameContextKey).(string); ok {
		return val
	}
	return ""
}

// GetRequestID returns the request ID from the request context, or "unknown" if not set.
func GetRequestID(r *http.Request) string {
	if rs := GetRequestState(r); rs != nil && rs.RequestID != "" {
		return rs.RequestID
	}
	return request.GetID(r)
}

// IsInternalPath returns true if the given path belongs to Gateon's internal API,
// monitoring, or health-check system.
func IsInternalPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/metrics" || path == "/healthz" || path == "/readyz" ||
		IsDashboardPath(path) || path == "/grpc.health.v1.Health/Check"
}

// IsDashboardPath returns true if the path is a Gateon dashboard gRPC-Web service.
func IsDashboardPath(path string) bool {
	return strings.HasPrefix(path, "/gateon.v1.ApiService/") || strings.HasPrefix(path, "/gateon.v1.AIService/")
}

// ShouldSkipMetrics determines if Prometheus metrics recording should be skipped
// for a given request. It skips metrics for the management entrypoint and internal
// paths, unless it's a dedicated proxy route (non-gateon prefix).
func ShouldSkipMetrics(r *http.Request) bool {
	if rs := GetRequestState(r); rs != nil {
		if rs.IsManagement {
			return true
		}
		if strings.HasPrefix(rs.RouteName, "gateon-") && IsInternalPath(r.URL.Path) {
			return true
		}
		return false
	}

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

// IsCorsPreflight returns true if the request is a CORS preflight request.
func IsCorsPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
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
					logger.L.LogError("handler panic recovered",
						"panic", err,
						"path", r.URL.Path,
						"method", r.Method,
						"stack", string(debug.Stack()))
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersConfig defines presets for common security headers.
type SecurityHeadersConfig struct {
	Preset string // "recommended", "strict", "none"
	// ExtraImgSrc adds additional sources to the CSP img-src directive on top
	// of the preset baseline. It is intended for first-party surfaces that must
	// load images from a known third party (e.g. the management UI's diagnostics
	// map, which pulls basemap tiles from a tile CDN). It is deliberately NOT
	// wired into the user-facing security_headers middleware so that attaching
	// the preset to a proxied backend never silently widens that backend's CSP.
	ExtraImgSrc []string
}

// SecurityHeaders returns a middleware that adds standard security headers to all responses based on a preset.
func SecurityHeaders(cfg SecurityHeadersConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			secure := isSecureRequest(r)
			switch cfg.Preset {
			case "recommended":
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "SAMEORIGIN")
				w.Header().Set("X-XSS-Protection", "0")
				w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
				w.Header().Set("Content-Security-Policy", contentSecurityPolicy(secure, cfg.ExtraImgSrc))
				w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
				if secure {
					w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
				}
			case "strict":
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "DENY")
				w.Header().Set("X-XSS-Protection", "0")
				w.Header().Set("Referrer-Policy", "no-referrer")
				w.Header().Set("Content-Security-Policy", contentSecurityPolicy(secure, cfg.ExtraImgSrc))
				w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
				if secure {
					w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
				}
			default:
				// Default legacy behavior if preset is empty or unknown
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "SAMEORIGIN")
				w.Header().Set("X-XSS-Protection", "1; mode=block")
				w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// contentSecurityPolicy returns the CSP value for the security-header presets.
// The upgrade-insecure-requests directive is only included for secure (HTTPS)
// requests; emitting it over plain HTTP would force browsers to upgrade
// same-origin asset requests to https://, which fails against an HTTP-only
// listener (e.g. the management UI on http://localhost) and breaks the page.
func contentSecurityPolicy(secure bool, extraImgSrc []string) string {
	imgSrc := "'self' data:"
	if len(extraImgSrc) > 0 {
		imgSrc += " " + strings.Join(extraImgSrc, " ")
	}
	csp := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src " + imgSrc + "; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"
	if secure {
		csp += " upgrade-insecure-requests;"
	}
	return csp
}

// isSecureRequest reports whether the request reached the server over a secure
// (TLS) connection, either directly or via a trusted TLS-terminating proxy.
// Trust of X-Forwarded-Proto is centralized in request.Scheme, which honors
// GATEON_TRUSTED_PROXIES so an untrusted client cannot spoof the scheme.
func isSecureRequest(r *http.Request) bool {
	return request.IsSecure(r)
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

// RealIP returns a middleware that resolves the real client IP and updates r.RemoteAddr.
// This ensures that all downstream middlewares see the real client IP instead of a proxy IP.
// It also ensures that the original scheme (http/https) is preserved via a context override
// before r.RemoteAddr is changed, which would otherwise break trusted-proxy detection.
func RealIP(trustCloudflare bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Resolve Client IP
			clientIP := request.GetClientIP(r, trustCloudflare)

			// If the immediate peer is a trusted proxy (including Cloudflare if enabled),
			// capture the forwarded proto before we lose the peer IP in r.RemoteAddr.
			if request.IsTrusted(r.RemoteAddr, trustCloudflare) {
				if proto := request.NormalizeProto(r.Header.Get(request.HeaderXForwardedProto)); proto != "" {
					r = r.WithContext(request.WithForwardedProto(r.Context(), proto))
				}
			}

			// Maintain the original port if present in RemoteAddr, as some components
			// (like PROXY protocol generation) expect a host:port format.
			if last := strings.LastIndexByte(r.RemoteAddr, ':'); last != -1 && !strings.HasSuffix(r.RemoteAddr, "]") {
				r.RemoteAddr = clientIP + r.RemoteAddr[last:]
			} else {
				r.RemoteAddr = clientIP
			}
			next.ServeHTTP(w, r)
		})
	}
}
