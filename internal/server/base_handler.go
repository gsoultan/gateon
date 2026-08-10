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

	// Built unconditionally, and deliberately not guarded on whether auth is
	// available *right now*. deps.Auth is a stable reference (an auth.Holder)
	// whose backing service arrives later, when Setup runs. Deciding here
	// whether to build the authenticating handler would freeze that decision at
	// construction time: on a first run there is no service yet, so the handler
	// would never be built, and the gateway would answer "setup incomplete"
	// forever — the same shape of bug as serving unauthenticated forever.
	//
	// PasetoAuth denies when its verifier cannot verify, so an unavailable
	// service fails closed on its own.
	authInternal := middleware.PasetoAuth(deps.Auth, middleware.AuthBaseConfig{})(finalInternal)

	// mgmtLogic defines the internal handler for management API, UI, and auth.
	// It is separated so that MgmtCORS can be applied only to this path.
	mgmtLogic := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gc := deps.GlobalReg.Get(r.Context())
		epID := ""
		if rs := middleware.GetRequestState(r); rs != nil {
			epID = rs.EntryPointID
		} else if id, ok := r.Context().Value(middleware.EntryPointIDContextKey).(string); ok {
			epID = id
		}

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
			// No auth service yet: fail closed. This is the first-run window,
			// before Setup has created an administrator. Serving the API here
			// (as this branch used to) meant a fresh gateway on a routable
			// address handed its full management surface — routes, services,
			// TLS material, config import — to whoever reached it first, with
			// no credential at all. Setup and health are already handled above;
			// everything else waits until there is something to authenticate
			// against.
			// Checked per request, not captured at construction: the Holder is
			// empty on a first run and filled in by Setup mid-process, so this
			// flips from 503 to real enforcement without a restart.
			if !auth.Available(deps.Auth) {
				writeAuthUnavailable(w, r)
				return
			}
			// Require Authorization header; accepts auth token in URL for WebSockets/SSE.
			authInternal.ServeHTTP(w, r)
			return
		}

		finalInternal.ServeHTTP(w, r)
	})

	var mgmtHandler http.Handler = mgmtLogic
	if deps.MgmtCORS != nil {
		mgmtHandler = deps.MgmtCORS.Handler(mgmtLogic)
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
		isMgmt := epID == "management"

		// Rule: Proxy routes generally take precedence over management logic.
		// On the management entrypoint, we are more restrictive: proxy routes only win if
		// they don't overlap with management API paths, UNLESS the route has an explicit
		// Host() rule (indicating explicit intent to host that domain's traffic).
		rt := router.SelectRoute(r, deps.RouteStore)
		if rt != nil {
			canShadow := !isMgmt || !isGateonManagementAPIPath(r.URL.Path) || router.RouteHasHostRule(rt.Rule)
			if canShadow {
				if rs := middleware.GetRequestState(r); rs != nil {
					rs.TRoute = time.Now().UnixNano()
					rs.MatchedRoute = rt
					handler.ServeHTTP(w, r)
				} else {
					ctx := context.WithValue(r.Context(), middleware.MatchedRouteContextKey, rt)
					handler.ServeHTTP(w, r.WithContext(ctx))
				}
				return
			}
		}

		// Security: If no user route matched on a NON-management entrypoint,
		// block access to the internal API/UI unless explicitly allowed.
		isMgmtAPI := (isMgmt || allowPublic) && isGateonManagementAPIPath(r.URL.Path)
		if !isMgmt && !isMgmtAPI && !isHealthPath(r.URL.Path) && !allowPublic {
			http.NotFound(w, r)
			return
		}

		mgmtHandler.ServeHTTP(w, r)
	})

	// Apply Telemetry at the edge to ensure it covers all responses.
	// MgmtCORS is now applied conditionally inside mainHandler for better isolation.
	return middleware.Telemetry("gateon")(mainHandler)
}
