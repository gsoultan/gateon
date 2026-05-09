package logger

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/request"
)

// SecurityEvent logs a security-relevant event for audit and monitoring.
func SecurityEvent(event string, r *http.Request, reason string) {
	L.LogWarn("security event",
		"event", event,
		"request_id", request.GetID(r),
		"ip", clientIP(r),
		"path", r.URL.Path,
		"reason", reason,
	)
}

// RBACPermissionDenied logs an RBAC denial for audit.
func RBACPermissionDenied(r *http.Request, userID, role, action, resource string) {
	L.LogWarn("RBAC permission denied",
		"event", "rbac_permission_denied",
		"request_id", request.GetID(r),
		"ip", clientIP(r),
		"path", r.URL.Path,
		"method", r.Method,
		"user_id", userID,
		"role", role,
		"action", action,
		"resource", resource,
	)
}

func clientIP(r *http.Request) string {
	return request.GetClientIP(r, request.TrustCloudflareFromEnv())
}
