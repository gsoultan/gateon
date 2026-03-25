package logger

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/request"
)

// SecurityEvent logs a security-relevant event for audit and monitoring.
func SecurityEvent(event string, r *http.Request, reason string) {
	L.Warn().
		Str("event", event).
		Str("ip", clientIP(r)).
		Str("path", r.URL.Path).
		Str("reason", reason).
		Msg("security event")
}

// RBACPermissionDenied logs an RBAC denial for audit.
func RBACPermissionDenied(r *http.Request, userID, role, action, resource string) {
	L.Warn().
		Str("event", "rbac_permission_denied").
		Str("ip", clientIP(r)).
		Str("path", r.URL.Path).
		Str("method", r.Method).
		Str("user_id", userID).
		Str("role", role).
		Str("action", action).
		Str("resource", resource).
		Msg("RBAC permission denied")
}

func clientIP(r *http.Request) string {
	return request.GetClientIP(r, request.TrustCloudflareFromEnv())
}
