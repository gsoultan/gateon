// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	mwauth "github.com/gsoultan/gateon/internal/middleware/auth"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/middleware/traffic"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/server/entrypoint"
	"github.com/gsoultan/gateon/internal/server/mgmtorigin"
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
	LoginLimiter traffic.RateLimiter // stricter rate limit for /v1/login (e.g. 5/min per IP)
	MgmtCORS     *cors.Cors
	// MgmtOrigins names the origins, besides the management origin itself,
	// that may write with the session cookie. Nil trusts none; the guard runs
	// either way.
	MgmtOrigins *mgmtorigin.Policy
}

// publicBodyLimit caps the body of a request to an endpoint served before
// authentication -- login, setup, the 2FA steps (ADR 0042). Every other
// management endpoint authenticates before it reads a byte of its body, so
// these are the only ones whose body anyone can make the gateway buffer, and
// each was allowed the 10 MiB every authenticated endpoint is: one address at
// the per-address connection cap could have it holding gigabytes. Their real
// bodies are credentials, a code, and setup's names, addresses and database
// settings -- a few hundred bytes.
const publicBodyLimit = 64 << 10

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
		traffic.Compress(),
		middleware.SecurityHeaders(middleware.SecurityHeadersConfig{Preset: "recommended", ExtraImgSrc: managementImgSrc}),
		security.XSSRecognition("gateon-management"),
		security.SQLiRecognition("gateon-management"),
		security.ThreatRecognition("gateon-management"),
		traffic.ManagementInflight(500), // probes take no slot (MGMT-N4)
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
		if isCacheableManagementAnswer(r) {
			// An answer holds configuration, users and audit entries. Set
			// before any handler runs so an error answer carries it too.
			w.Header().Set("Cache-Control", "no-store")
		}
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
				handleLoginWithRateLimit(w, withAuthNotRequired(r), finalInternal, deps)
				return
			}
			if isPublicAuthPath(r.URL.Path) {
				finalInternal.ServeHTTP(w, withAuthNotRequired(r))
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
			// A scrape credential on /metrics, and only there (ADR 0050).
			if serveScrape(w, r, deps.Auth, finalInternal) {
				return
			}
			// Require Authorization header; accepts auth token in URL for WebSockets/SSE.
			authInternal.ServeHTTP(w, r)
			return
		}

		// Authentication is off for this deployment and this is not the
		// management entrypoint: the one case in which the API runs with no
		// caller. The authorization checks allow a request with no claims only
		// when this mark says so.
		finalInternal.ServeHTTP(w, withAuthNotRequired(r))
	})

	var mgmtHandler http.Handler = mgmtLogic
	if deps.MgmtCORS != nil {
		mgmtHandler = deps.MgmtCORS.Handler(mgmtLogic)
	}
	// Outside CORS, so a refused request is answered with no CORS headers,
	// and around everything the management plane serves -- sign-in and setup
	// included, which are writes too. Not conditional: it is the only thing
	// that tells a write the dashboard asked for from one another page on the
	// same site did with the dashboard's cookie (ADR 0041).
	mgmtHandler = deps.MgmtOrigins.Guard(mgmtHandler)

	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit request body size to prevent DoS via large payloads.
		// Default is 10MB, but GeoIP database uploads can be much larger.
		limit := int64(10 * 1024 * 1024)
		switch {
		case r.URL.Path == "/v1/geoip/upload":
			limit = 512 * 1024 * 1024 // 512MB for GeoIP database
		case isLoginPath(r.URL.Path) || isPublicAuthPath(r.URL.Path):
			limit = publicBodyLimit
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

		// Rule: Proxy routes take precedence over management logic, except for a
		// request the internal management API will answer.
		//
		// The branch below hands the request straight to the proxy handler, which
		// skips mgmtHandler -- and mgmtHandler is where authentication happens.
		// HandleProxyOrLocal never proxies a management-API path in this context:
		// it serves it from the internal mux. So a route matching one here hosted
		// nobody's traffic; it only removed authentication from the management
		// API. That is what an explicit Host() rule used to do on the management
		// entrypoint, and since a Host() route matches every path on its host, one
		// ordinary vhost route was enough to serve the whole API, the global
		// config's signing key included, to a caller with no credential.
		//
		// Decided after SelectRoute, which normalises the path both checks read.
		rt := router.SelectRoute(r, deps.RouteStore)
		isMgmtAPI := (isMgmt || allowPublic) && isGateonManagementAPIPath(r.URL.Path)
		if rt != nil && !isMgmtAPI {
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

		// Security: If no user route matched on a NON-management entrypoint,
		// block access to the internal API/UI unless explicitly allowed.
		if !isMgmt && !isMgmtAPI && !isHealthPath(r.URL.Path) && !allowPublic {
			http.NotFound(w, r)
			return
		}

		mgmtHandler.ServeHTTP(w, r)
	})

	// Apply Telemetry at the edge to ensure it covers all responses.
	// MgmtCORS is now applied conditionally inside mainHandler for better isolation.
	return withholdFromDataPlane(deps, middleware.Telemetry("gateon")(mainHandler))
}

// withholdFromDataPlane removes the management plane's credentials -- the
// session cookie under either name, a session as a bearer token, a scrape
// token -- from every request the management plane will not answer, before
// route matching and before any route middleware runs (ADR 0051).
//
// The proxy already withheld them from the backend (ADR 0041), but the route's
// middlewares run before the proxy, and some of them send the request on:
// forwardauth copies every header to its auth server, OAuth2 introspection
// posts the request's token to its endpoint. A browser sends the dashboard's
// cookie to every app on the dashboard's host, so an operator who bound either
// middleware to a route, pointed at a server of their own, was handed the
// administrator's session. And since a route's JWT, PASETO and introspection
// checks read the session cookie ahead of the app's own bearer token, they
// refused the administrator's browser whatever app token it presented.
//
// A request with nothing that could be a management credential -- nearly all
// of them -- pays one scan of its Cookie and Authorization values, and nothing
// is allocated or verified.
func withholdFromDataPlane(deps BaseHandlerDeps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mwauth.MayCarryManagementCredential(r.Header) {
			if managementBound(r, deps.GlobalReg) {
				next.ServeHTTP(w, r)
				return
			}
			mwauth.WithholdManagementCredentials(r.Header, deps.Auth)
		}
		// Withheld, or nothing to withhold: either way the proxy need not
		// verify a session bearer again. A request the management plane
		// answers is never proxied, and is not marked.
		if rs := middleware.GetRequestState(r); rs != nil {
			rs.CredentialsWithheld = true
		}
		next.ServeHTTP(w, r)
	})
}

// managementBound reports whether the management plane, rather than a route,
// will answer r: everything on the management listener or on an entrypoint
// sharing its address (HandleProxyOrLocal never proxies those), and the
// management API on an entrypoint allowed to serve it. It is the decision
// mainHandler makes after SelectRoute, taken before it, so the path is read as
// SelectRoute will normalise it: "/v1/status/../../app" is the app's.
func managementBound(r *http.Request, globalReg config.GlobalConfigStore) bool {
	epID, isMgmt := requestEntrypoint(r)
	if isMgmt || epID == "management" {
		return true
	}
	return isGateonManagementAPIPath(router.NormalizePath(r.URL.Path)) &&
		isPublicManagementAllowed(r, epID, globalReg)
}

// requestEntrypoint returns the ID of the entrypoint r arrived on, and whether
// that entrypoint is the management plane's address.
func requestEntrypoint(r *http.Request) (string, bool) {
	if rs := middleware.GetRequestState(r); rs != nil {
		return rs.EntryPointID, rs.IsManagement
	}
	epID, _ := r.Context().Value(middleware.EntryPointIDContextKey).(string)
	isMgmt, _ := r.Context().Value(middleware.IsManagementContextKey).(bool)
	return epID, isMgmt
}

// withAuthNotRequired marks r as needing no credential; see
// middleware.AuthNotRequired. Only this file's no-credential branches use it.
func withAuthNotRequired(r *http.Request) *http.Request {
	return r.WithContext(middleware.WithAuthNotRequired(r.Context()))
}
