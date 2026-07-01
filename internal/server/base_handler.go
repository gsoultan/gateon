package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/rs/cors"
)

// managementImgSrc lists the third-party image hosts the management UI must be
// allowed to load. The diagnostics "Anomaly Intelligence Engine" map renders
// basemap tiles served from CARTO's tile CDN (a/b/c/d.basemaps.cartocdn.com),
// so those tiles need an explicit img-src entry; the baseline CSP only permits
// 'self' and data: URIs. This widening is applied ONLY to the management UI
// handler below — never to proxied backends.
var managementImgSrc = []string{"https://*.basemaps.cartocdn.com"}

// BaseHandlerDeps holds narrow dependencies for CreateBaseHandler (Interface Segregation).
// Auth may be nil when auth is disabled.
type BaseHandlerDeps struct {
	ProxyHandler http.Handler
	RouteStore   config.RouteStore
	GlobalReg    config.GlobalConfigStore
	Auth         auth.Service
	LoginLimiter middleware.RateLimiter // stricter rate limit for /v1/login (e.g. 5/min per IP)
	MgmtCORS     *cors.Cors
}

// CreateBaseHandler builds the main HTTP handler that routes to proxy or local API/UI.
func CreateBaseHandler(
	uiHandler http.Handler,
	deps BaseHandlerDeps,
	grpcWeb entrypoint.GRPCWebHandler,
	mux *http.ServeMux,
) http.Handler {
	handler := deps.ProxyHandler
	_ = grpcWeb // reserved for future gRPC-web routing in base handler

	internalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/gateon.v1.") ||
			r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			handler.ServeHTTP(w, r)
			return
		}
		uiHandler.ServeHTTP(w, r)
	})

	// 1. Recovery from panics
	// 2. Security Headers (Recommended preset with CSP)
	// 3. XSS Recognition (Lightweight monitoring)
	// 4. Max Connections limit
	// Pre-chain middlewares to avoid per-request allocations.
	finalInternal := middleware.Chain(
		middleware.Recovery(),
		middleware.Nonce(),
		func(next http.Handler) http.Handler {
			if deps.MgmtCORS != nil {
				return deps.MgmtCORS.Handler(next)
			}
			return next
		},
		middleware.SecurityHeaders(middleware.SecurityHeadersConfig{Preset: "recommended", ExtraImgSrc: managementImgSrc}),
		middleware.XSSRecognition("gateon-management"),
		middleware.MaxConnections(500),
	)(internalHandler)

	var authInternal http.Handler
	if deps.Auth != nil {
		authInternal = middleware.PasetoAuth(deps.Auth, middleware.AuthBaseConfig{})(finalInternal)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit request body size to prevent DoS via large payloads.
		// Default is 10MB, but GeoIP database uploads can be much larger.
		limit := int64(10 * 1024 * 1024)
		if r.URL.Path == "/v1/geoip/upload" {
			limit = 512 * 1024 * 1024 // 512MB for GeoIP database
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)

		epID, _ := r.Context().Value(middleware.EntryPointIDContextKey).(string)

		// On the management entrypoint, we do NOT serve user-defined proxy routes.
		if epID != "management" {
			if rt := router.SelectRoute(r, deps.RouteStore); rt != nil {
				// Avoid double-routing in HandleProxyOrLocal by passing the matched route in context.
				if rs := middleware.GetRequestState(r); rs != nil {
					rs.MatchedRoute = rt
					handler.ServeHTTP(w, r)
				} else {
					ctx := context.WithValue(r.Context(), middleware.MatchedRouteContextKey, rt)
					handler.ServeHTTP(w, r.WithContext(ctx))
				}
				return
			}

			// Security: If no user route matched on a NON-management entrypoint,
			// block access to the internal API/UI unless explicitly allowed.
			if !isHealthPath(r.URL.Path) {
				gc := deps.GlobalReg.Get(r.Context())
				allowPublic := false
				if gc != nil && gc.Management != nil {
					allowPublic = gc.Management.AllowPublicManagement
					if !allowPublic && len(gc.Management.AllowedHosts) > 0 {
						host := r.Host
						if h, _, err := net.SplitHostPort(r.Host); err == nil {
							host = h
						}
						for _, allowedHost := range gc.Management.AllowedHosts {
							if host == allowedHost {
								allowPublic = true
								break
							}
						}
					}
				}
				if os.Getenv("GATEON_ALLOW_PUBLIC_MANAGEMENT") == "true" {
					allowPublic = true
				}
				if !allowPublic {
					http.NotFound(w, r)
					return
				}
			}
		}

		gc := deps.GlobalReg.Get(r.Context())
		// Management entrypoint ALWAYS requires auth checks for API paths,
		// even if auth is disabled globally for the gateway's proxy traffic.
		if needsAuth(gc, deps) || epID == "management" {
			if !isAPIMetricsPath(r.URL.Path) {
				finalInternal.ServeHTTP(w, r)
				return
			}
			if isLoginPath(r.URL.Path) {
				handleLoginWithRateLimit(w, r, finalInternal, deps)
				return
			}
			if isPublicAuthPath(r.URL.Path) {
				finalInternal.ServeHTTP(w, r)
				return
			}
			if deps.Auth == nil || authInternal == nil {
				// No auth service available yet (e.g. first run)
				finalInternal.ServeHTTP(w, r)
				return
			}
			// Require Authorization header; do not accept auth token in URL.
			authInternal.ServeHTTP(w, r)
			return
		}

		finalInternal.ServeHTTP(w, r)
	})
}
