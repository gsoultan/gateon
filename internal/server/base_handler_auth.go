// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/auth/admission"
	"github.com/gsoultan/gateon/internal/auth/apitoken"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/grpc/codes"
)

// needsAuth returns true when global config has auth enabled and auth service is available.
func needsAuth(gc *gateonv1.GlobalConfig, deps BaseHandlerDeps) bool {
	return gc != nil && gc.Auth != nil && gc.Auth.Enabled && auth.Available(deps.Auth)
}

// writeAuthUnavailable rejects a management request made before an auth service
// exists. 503 (not 401) is deliberate: there is no credential the caller could
// present that would work, and the correct operator action is to finish setup,
// so this is a server-state problem rather than a rejected identity.
func writeAuthUnavailable(w http.ResponseWriter, r *http.Request) {
	logger.SecurityEvent("management_api_before_setup", r, "auth_unavailable")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"error":"setup incomplete: the management API is unavailable until an administrator account has been created"}`))
}

// isPublicManagementAllowed returns true if management access is allowed for this entrypoint/request.
func isPublicManagementAllowed(r *http.Request, epID string, globalReg config.GlobalConfigStore) bool {
	if epID == "management" {
		return true
	}
	if os.Getenv("GATEON_ALLOW_PUBLIC_MANAGEMENT") == "true" {
		return true
	}
	if globalReg == nil {
		return false
	}
	gc := globalReg.Get(r.Context())
	if gc != nil && gc.Management != nil {
		if gc.Management.AllowPublicManagement {
			return true
		}
		if len(gc.Management.AllowedHosts) > 0 {
			host := r.Host
			if h, _, err := net.SplitHostPort(r.Host); err == nil {
				host = h
			}
			for _, allowedHost := range gc.Management.AllowedHosts {
				if host == allowedHost {
					return true
				}
			}
		}
	}
	return false
}

// isAPIMetricsPath returns true for /v1/*, /gateon.v1.*, or /metrics.
func isAPIMetricsPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || strings.HasPrefix(path, "/gateon.v1.") || path == "/metrics"
}

// isCacheableManagementAnswer reports whether r is answered by the management
// API, REST or Connect, with a method whose answer a cache may keep: GET, HEAD
// and POST are the only ones RFC 9111 allows. Connect calls are POSTs (or GETs).
//
// PUT, PATCH and DELETE answers are never stored, so they get no header to say
// so. Saying it anyway is not harmless: Chromium then keeps no copy of a PUT
// answer's body for its inspector, which every Playwright spec that reads the
// answer to the dashboard's PUT /v1/global waits on until it times out.
func isCacheableManagementAnswer(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		return false
	}
	return strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/gateon.v1.")
}

// isGateonManagementAPIPath returns true for Gateon internal management API and ConnectRPC endpoints.
func isGateonManagementAPIPath(path string) bool {
	if path == "/metrics" || path == "/healthz" || path == "/readyz" || path == "/grpc.health.v1.Health/Check" {
		return true
	}
	if strings.HasPrefix(path, "/gateon.v1.") {
		return true
	}
	if !strings.HasPrefix(path, "/v1/") {
		return false
	}
	mgmtPrefixes := []string{
		"/v1/status",
		"/v1/agg-stats",
		"/v1/path-stats",
		"/v1/requests-per-second",
		"/v1/limit-stats",
		"/v1/global",
		"/v1/routes",
		"/v1/services",
		"/v1/entrypoints",
		"/v1/middlewares",
		"/v1/tls-options",
		"/v1/certificates",
		"/v1/certs",
		"/v1/diagnostics",
		"/v1/diag",
		"/v1/logs",
		"/v1/traces",
		"/v1/security",
		"/v1/ai-advisory",
		"/v1/waf-rules",
		"/v1/watch",
		"/v1/login",
		"/v1/setup",
		"/v1/geoip",
		"/v1/config",
		"/v1/auth",
		"/v1/canary",
		"/v1/AnalyzeConfig",
		"/v1/AnalyzeLogs",
		"/v1/users",
		"/v1/api-tokens",
		"/v1/client-authorities",
		"/v1/system",
		"/v1/openapi",
	}
	for _, p := range mgmtPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") || strings.HasPrefix(path, p+"?") {
			return true
		}
	}
	return false
}

// serveScrape answers GET /metrics for a request carrying a scrape credential
// -- an API token with the metrics:read scope -- and reports whether the
// request carried one (ADR 0050). A request that does not is left to the
// session check. /metrics used to accept only a user's eight-hour session, so
// a scraper needed a viewer account, its password on disk and a timer signing
// in again every few hours.
//
// It is the only place a token is accepted. PasetoAuth does not recognise the
// format, so on every other path, and on every transport, a token is refused
// as an invalid session; and the token never reaches the API handlers, so it
// carries no claims and no role.
func serveScrape(w http.ResponseWriter, r *http.Request, svc auth.Service, next http.Handler) bool {
	if r.URL.Path != "/metrics" {
		return false
	}
	token, ok := apitoken.BearerToken(r.Header.Get("Authorization"))
	if !ok {
		return false
	}
	store := svc.APITokens()
	if store == nil {
		writeScrapeRefused(w)
		return true
	}
	if _, err := store.Verify(r.Context(), token, apitoken.ScopeMetricsRead); err != nil {
		if !errors.Is(err, apitoken.ErrInvalid) {
			logger.L.LogError("a scrape credential could not be checked", "error", err)
		}
		logger.SecurityEvent("scrape_token_refused", r, "invalid_expired_revoked_or_unscoped")
		writeScrapeRefused(w)
		return true
	}
	next.ServeHTTP(w, r)
	return true
}

func writeScrapeRefused(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", `Bearer realm="gateon-metrics"`)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"the api token is not valid for /metrics"}`))
}

// isLoginPath returns true for /v1/login or /gateon.v1.ApiService/Login.
func isLoginPath(path string) bool {
	return path == "/v1/login" || path == "/gateon.v1.ApiService/Login"
}

// publicAuthPaths are the exact paths served before Paseto auth runs.
//
// "/v1/setup/test-db" is the wizard's connection test, and it belongs here for
// the same reason "/v1/setup" does: it runs before an administrator exists, so
// there is no credential to present. Without it the base handler answered 503
// during first run while the handler itself answers 403 once setup completes --
// no reachable state, and the wizard's button always failed.
//
// It is the narrowest addition that works. Membership is exact rather than
// prefixed on purpose: HasPrefix("/v1/setup") would make every future
// /v1/setup/* endpoint unauthenticated by accident, and the handler behind this
// one opens a database connection to a caller-supplied DSN. That is an
// outbound-connection primitive, so it is bounded twice -- by this list, and by
// the handler refusing once setup is done.
//
// The 2FA pair is the login flow's two pre-session steps, and only those.
// "/v1/auth/2fa/setup" is deliberately absent: it returns the TOTP secret, the
// QR code and the recovery codes, so it authenticates and then refuses any id
// but the caller's own.
//
// A set rather than a chain of ||, so the entries can be enumerated and
// checked. Two of them named procedures that do not exist --
// ApiService/Enroll2FA and ApiService/Verify2FA, which have REST equivalents
// but no RPC. They matched nothing, so they were harmless; they would have
// stopped being harmless the moment someone added those RPCs, because the
// procedure would have arrived already exempt from authentication. That is
// exactly the accident the exact-match rule above is written to prevent,
// reached by name instead of by prefix.
var publicAuthPaths = map[string]struct{}{
	"/v1/setup":                             {},
	"/v1/setup/required":                    {},
	"/v1/setup/test-db":                     {},
	"/gateon.v1.ApiService/Setup":           {},
	"/gateon.v1.ApiService/IsSetupRequired": {},
	"/v1/auth/2fa/enroll":                   {},
	"/v1/auth/2fa/verify":                   {},
}

// isPublicAuthPath returns true for setup, health, status, or login — these skip Paseto auth.
func isPublicAuthPath(path string) bool {
	if _, ok := publicAuthPaths[path]; ok {
		return true
	}
	return isHealthPath(path)
}

// isHealthPath returns true for /healthz, /readyz, or gRPC health check.
func isHealthPath(path string) bool {
	return path == "/healthz" || path == "/readyz" || path == "/grpc.health.v1.Health/Check"
}

// passwordCheckPaths are the endpoints served without a session that can
// reach a password check, a 2FA code check or the sign-in lockout -- or, for
// setup's connection test, open a connection -- over REST, Connect and gRPC.
// Every request to one spends from its client's budget first (ADR 0053).
//
// Only /v1/login used to have a budget, five a minute. POST /v1/auth/2fa/enroll
// takes the same password step and had none: from one address it answered
// 18,252 times in 75 s, each a bcrypt at the production cost (an unknown name
// costs one too, ADR 0050), never once 429. One budget for all of them, so a
// client cannot spend five on each.
//
// IsSetupRequired and /v1/setup/required are absent: they read one row and
// the dashboard polls them.
var passwordCheckPaths = map[string]struct{}{
	"/v1/login":                   {},
	"/gateon.v1.ApiService/Login": {},
	"/v1/auth/2fa/enroll":         {},
	"/v1/auth/2fa/verify":         {},
	"/v1/setup":                   {},
	"/v1/setup/test-db":           {},
	"/gateon.v1.ApiService/Setup": {},
}

// publicAuthRefusal is what a refused client is told, on every protocol.
const publicAuthRefusal = "too many sign-in requests from this address; try again later"

// refusalLog spaces the log lines refusals write: each is counted, but a
// flood of them must not become a flood of log lines.
var refusalLog limitWarning

// admitPublicAuth spends one request from the client's budget when r is for
// one of passwordCheckPaths, and reports whether it may proceed. A refused
// request is answered here, before its body is read and before any hash, so
// its answer is the same whatever username it carries.
func admitPublicAuth(w http.ResponseWriter, r *http.Request, budget *admission.Sources) bool {
	if _, ok := passwordCheckPaths[r.URL.Path]; !ok {
		return true
	}
	ok, wait := budget.Take(request.ClientAddr(r))
	if ok {
		return true
	}
	telemetry.IncRateLimitRejected("local")
	if refusalLog.due(time.Now()) {
		logger.SecurityEvent("public_auth_rate_limit", r, "too_many_attempts")
	}
	writeTooManyAttempts(w, r, wait)
	return false
}

// writeTooManyAttempts answers 429 with Retry-After, in the shape the caller's
// protocol reads: a gRPC status (ResourceExhausted, in a trailers-only answer)
// to a gRPC or gRPC-Web call, a Connect error to a Connect call, and the REST
// API's JSON error to anything else.
func writeTooManyAttempts(w http.ResponseWriter, r *http.Request, wait time.Duration) {
	h := w.Header()
	h.Set("Retry-After", strconv.Itoa(max(1, int(wait/time.Second))))
	h.Set("Cache-Control", "no-store")
	switch {
	case strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc"):
		h.Set("Content-Type", r.Header.Get("Content-Type"))
		h.Set("Grpc-Status", strconv.Itoa(int(codes.ResourceExhausted)))
		h.Set("Grpc-Message", publicAuthRefusal)
		w.WriteHeader(http.StatusOK)
	case strings.HasPrefix(r.URL.Path, "/gateon.v1."):
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":"resource_exhausted","message":"` + publicAuthRefusal + `"}`))
	default:
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"` + publicAuthRefusal + `"}`))
	}
}

// limitWarning is when something last logged, in unix nanoseconds.
type limitWarning struct{ last atomic.Int64 }

// due reports whether a refusal at now should log: at most once a minute.
func (l *limitWarning) due(now time.Time) bool {
	last := l.last.Load()
	if now.UnixNano()-last < int64(time.Minute) {
		return false
	}
	return l.last.CompareAndSwap(last, now.UnixNano())
}
