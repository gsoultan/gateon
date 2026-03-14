package handlers

import (
	"net/http"

	"github.com/gateon/gateon/internal/auth"
	"github.com/gateon/gateon/internal/logger"
	"github.com/gateon/gateon/internal/middleware"
)

// RequirePermission checks that the request has a valid user with permission for the action on resource.
// When auth is disabled (no PasetoAuth), claims are nil and we allow. Returns false if forbidden.
func RequirePermission(w http.ResponseWriter, r *http.Request, action auth.Action, resource auth.Resource) bool {
	claimsVal := r.Context().Value(middleware.UserContextKey)
	if claimsVal == nil {
		// Auth disabled: PasetoAuth never ran, allow
		return true
	}
	claims, ok := claimsVal.(*auth.Claims)
	if !ok || claims == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"permission denied"}`))
		return false
	}
	if !auth.Allowed(claims.Role, action, resource) {
		logger.RBACPermissionDenied(r, claims.ID, claims.Role, string(action), string(resource))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"insufficient permissions"}`))
		return false
	}
	return true
}
