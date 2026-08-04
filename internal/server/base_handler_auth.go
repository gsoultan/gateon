// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package server

import (
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	pkghttputil "github.com/gsoultan/gateon/pkg/httputil"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// needsAuth returns true when global config has auth enabled and auth service is available.
func needsAuth(gc *gateonv1.GlobalConfig, deps BaseHandlerDeps) bool {
	return gc != nil && gc.Auth != nil && gc.Auth.Enabled && deps.Auth != nil
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

// isLoginPath returns true for /v1/login or /gateon.v1.ApiService/Login.
func isLoginPath(path string) bool {
	return path == "/v1/login" || path == "/gateon.v1.ApiService/Login"
}

// isPublicAuthPath returns true for setup, health, status, or login — these skip Paseto auth.
func isPublicAuthPath(path string) bool {
	return path == "/v1/setup" || path == "/v1/setup/required" ||
		path == "/gateon.v1.ApiService/Setup" || path == "/gateon.v1.ApiService/IsSetupRequired" ||
		path == "/v1/auth/2fa/enroll" || path == "/v1/auth/2fa/verify" ||
		path == "/gateon.v1.ApiService/Enroll2FA" || path == "/gateon.v1.ApiService/Verify2FA" ||
		isHealthPath(path)
}

// isHealthPath returns true for /healthz, /readyz, or gRPC health check.
func isHealthPath(path string) bool {
	return path == "/healthz" || path == "/readyz" || path == "/grpc.health.v1.Health/Check"
}

// handleLoginWithRateLimit applies login rate limiting if configured, then serves internal.
func handleLoginWithRateLimit(w http.ResponseWriter, r *http.Request, internal http.Handler, deps BaseHandlerDeps) {
	if deps.LoginLimiter != nil {
		limited := deps.LoginLimiter.Handler(middleware.PerIP)(internal)
		sw := pkghttputil.GetStatusResponseWriter(w)
		defer pkghttputil.PutStatusResponseWriter(sw)

		limited.ServeHTTP(sw, r)
		if sw.Status == http.StatusTooManyRequests {
			logger.SecurityEvent("login_rate_limit", r, "too_many_attempts")
		}
		return
	}
	internal.ServeHTTP(w, r)
}
