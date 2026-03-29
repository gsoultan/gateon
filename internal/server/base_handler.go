package server

import (
	"net/http"
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

	return middleware.RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		epID, _ := r.Context().Value(middleware.EntryPointIDContextKey).(string)

		// On the management entrypoint, we do NOT serve user-defined proxy routes.
		if epID != "management" {
			if rt := router.SelectRoute(r, deps.RouteStore.List(r.Context())); rt != nil {
				handler.ServeHTTP(w, r)
				return
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
			middleware.PasetoAuth(deps.Auth)(internal).ServeHTTP(w, r)
			return
		}

		internal.ServeHTTP(w, r)
	}))
}
