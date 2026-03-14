package server

import (
	"net/http"
	"strings"

	"github.com/gateon/gateon/internal/httputil"
	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/middleware"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// needsAuth returns true when global config has auth enabled and auth service is available.
func needsAuth(gc *gateonv1.GlobalConfig, deps BaseHandlerDeps) bool {
	return gc != nil && gc.Auth != nil && gc.Auth.Enabled && deps.Auth != nil
}

// isAPIMetricsPath returns true for /v1/* or /metrics.
func isAPIMetricsPath(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/metrics"
}

// isLoginPath returns true for /v1/login.
func isLoginPath(path string) bool {
	return path == "/v1/login"
}

// isPublicAuthPath returns true for setup, health, status, or login — these skip Paseto auth.
func isPublicAuthPath(path string) bool {
	return path == "/v1/setup" || path == "/v1/setup/required" ||
		path == "/healthz" || path == "/readyz" || path == "/v1/status"
}

// handleLoginWithRateLimit applies login rate limiting if configured, then serves internal.
func handleLoginWithRateLimit(w http.ResponseWriter, r *http.Request, internal http.Handler, deps BaseHandlerDeps) {
	if deps.LoginLimiter != nil {
		limited := deps.LoginLimiter.Handler(middleware.PerIP)(internal)
		rec := &httputil.StatusRecorder{ResponseWriter: w, Status: 200}
		limited.ServeHTTP(rec, r)
		if rec.Status == http.StatusTooManyRequests {
			logger.SecurityEvent("login_rate_limit", r, "too_many_attempts")
		}
		return
	}
	internal.ServeHTTP(w, r)
}
