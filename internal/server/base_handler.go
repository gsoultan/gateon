package server

import (
	"net/http"
	"strings"

	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/config"
	"github.com/gateon/gateon/internal/middleware"
	"github.com/gateon/gateon/internal/router"
	"github.com/gateon/gateon/internal/server/entrypoint"
)

// BaseHandlerDeps holds narrow dependencies for CreateBaseHandler (Interface Segregation).
// Auth may be nil when auth is disabled.
type BaseHandlerDeps struct {
	ProxyHandler  http.Handler
	RouteStore    config.RouteStore
	GlobalReg     config.GlobalConfigStore
	Auth          auth.Service
	LoginLimiter  middleware.RateLimiter // stricter rate limit for /v1/login (e.g. 5/min per IP)
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
		if rt := router.SelectRoute(r, deps.RouteStore.List(r.Context())); rt != nil {
			handler.ServeHTTP(w, r)
			return
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
		if !needsAuth(gc, deps) {
			internal.ServeHTTP(w, r)
			return
		}
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
		// Require Authorization header for /v1/logs; do not accept auth token in URL (logs may expose it).
		middleware.PasetoAuth(deps.Auth)(internal).ServeHTTP(w, r)
	})
}
