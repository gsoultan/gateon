// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package server

import (
	"context"
	"net/http"
	"strings"
	"time"

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
		middleware.Compress(),
		middleware.SecurityHeaders(middleware.SecurityHeadersConfig{Preset: "recommended", ExtraImgSrc: managementImgSrc}),
		middleware.XSSRecognition("gateon-management"),
		middleware.SQLiRecognition("gateon-management"),
		middleware.ThreatRecognition("gateon-management"),
		middleware.MaxConnections(500),
	)(internalHandler)

	var authInternal http.Handler
	if deps.Auth != nil {
		authInternal = middleware.PasetoAuth(deps.Auth, middleware.AuthBaseConfig{})(finalInternal)
	}

	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit request body size to prevent DoS via large payloads.
		// Default is 10MB, but GeoIP database uploads can be much larger.
		limit := int64(10 * 1024 * 1024)
		if r.URL.Path == "/v1/geoip/upload" {
			limit = 512 * 1024 * 1024 // 512MB for GeoIP database
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)

		rs := middleware.GetRequestState(r)
		epID := ""
		if rs != nil {
			epID = rs.EntryPointID
		} else if id, ok := r.Context().Value(middleware.EntryPointIDContextKey).(string); ok {
			epID = id
		}

		allowPublic := isPublicManagementAllowed(r, epID, deps.GlobalReg)
		isMgmtAPI := allowPublic && isGateonManagementAPIPath(r.URL.Path)

		if epID != "management" && !isMgmtAPI {
			rt := router.SelectRoute(r, deps.RouteStore)
			if rs := middleware.GetRequestState(r); rs != nil {
				rs.TRoute = time.Now().UnixNano()
			}
			if rt != nil {
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
			if !isHealthPath(r.URL.Path) && !allowPublic {
				http.NotFound(w, r)
				return
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
			// Require Authorization header; accepts auth token in URL for WebSockets/SSE.
			authInternal.ServeHTTP(w, r)
			return
		}

		finalInternal.ServeHTTP(w, r)
	})

	// Apply Telemetry and CORS at the very edge to ensure they cover all responses, including auth failures.
	h := middleware.Telemetry("gateon")(mainHandler)
	if deps.MgmtCORS != nil {
		h = deps.MgmtCORS.Handler(h)
	}
	return h
}
