package server

import (
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
)

// BaseHandlerDeps holds narrow dependencies for CreateBaseHandler (Interface Segregation).
// Auth may be nil when auth is disabled.
type BaseHandlerDeps struct {
	ProxyHandler http.Handler
	RouteStore   config.RouteStore
	GlobalReg    config.GlobalConfigStore
	Auth         auth.Service
	LoginLimiter middleware.RateLimiter // stricter rate limit for /v1/login (e.g. 5/min per IP)
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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		epID, _ := r.Context().Value(middleware.EntryPointIDContextKey).(string)

		// On the management entrypoint, we do NOT serve user-defined proxy routes.
		if epID != "management" {
			if rt := router.SelectRoute(r, deps.RouteStore.List(r.Context())); rt != nil {
				handler.ServeHTTP(w, r)
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

		internalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/metrics" || r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				handler.ServeHTTP(w, r)
				return
			}
			uiHandler.ServeHTTP(w, r)
		})
		// Limit concurrent requests to internal API (dashboard, /v1/*, /metrics) to prevent DoS.
		internal := middleware.MaxConnections(500)(internalHandler)

		gc := deps.GlobalReg.Get(r.Context())
		// Management entrypoint ALWAYS requires auth checks for API paths,
		// even if auth is disabled globally for the gateway's proxy traffic.
		if needsAuth(gc, deps) || epID == "management" {
			if !isAPIMetricsPath(r.URL.Path) {
				internal.ServeHTTP(w, r)
				return
			}
			if isLoginPath(r.URL.Path) {
				handleLoginWithRateLimit(w, r, internal, deps)
				return
			}
			if isPublicAuthPath(r.URL.Path) {
				internal.ServeHTTP(w, r)
				return
			}
			if deps.Auth == nil {
				// No auth service available yet (e.g. first run)
				internal.ServeHTTP(w, r)
				return
			}
			// Require Authorization header; do not accept auth token in URL.
			middleware.PasetoAuth(deps.Auth, middleware.AuthBaseConfig{})(internal).ServeHTTP(w, r)
			return
		}

		internal.ServeHTTP(w, r)
	})
}
