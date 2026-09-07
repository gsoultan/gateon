// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
)

// RequirePermission checks that the request has a valid user with permission for the action on resource.
// When auth is disabled (no PasetoAuth), claims are nil and we allow. Returns false if forbidden.
func RequirePermission(w http.ResponseWriter, r *http.Request, action auth.Action, resource auth.Resource) bool {
	logger.L.LogDebug("checking permission", "path", r.URL.Path, "action", action, "resource", resource)
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
	if !auth.Allowed(r.Context(), claims.Role, action, resource) {
		logger.RBACPermissionDenied(r, claims.ID, claims.Role, string(action), string(resource))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"insufficient permissions"}`))
		return false
	}
	return true
}

// callerClaims resolves the authenticated caller for handlers that make their
// own authorization decision rather than delegating to RequirePermission.
//
// Three states, and the middle one is the reason this exists:
//
//   - no claims value at all -> (nil, true). Auth is disabled and PasetoAuth
//     never ran; RequirePermission permits the same case, and handlers that
//     want to refuse it can check for a nil claims.
//   - a value that is not *auth.Claims -> (nil, false). Something stored a
//     credential this handler cannot read. "I cannot tell who this is" must
//     never take the same branch as "there is nobody to check".
//   - a usable *auth.Claims -> (claims, true).
//
// Handlers previously wrote `if claims, ok := v.(*auth.Claims); ok && claims !=
// nil { ...check... }`, which silently skips the check when the assertion fails.
// There is one context key -- middleware.UserContextKey aliases
// auth.UserContextKey -- and one writer, InjectContext(ctx, claims any), which
// stores whatever it is given; the JWT middleware gives it jwt.MapClaims. The
// management plane authenticates with Paseto and gets *auth.Claims today, so
// this was latent, but nothing in the type system keeps the two apart and the
// endpoints concerned were the password change and 2FA enrolment.
func callerClaims(r *http.Request) (*auth.Claims, bool) {
	v := r.Context().Value(middleware.UserContextKey)
	if v == nil {
		return nil, true
	}
	claims, isClaims := v.(*auth.Claims)
	if !isClaims || claims == nil {
		return nil, false
	}
	return claims, true
}

// auditUser names the caller for an audit entry, or "system" when there is
// nobody to name.
//
// This was twelve copies of the same four lines, each asserting the context
// value to *auth.Claims with a discarded ok. Individually harmless -- the worst
// case is an entry attributed to "system" -- but they were indistinguishable at
// a glance from the two assertions that gated an authorization decision and
// skipped it when they failed. Collapsing the harmless ones to a single call
// leaves `.(*auth.Claims)` appearing in this file only, which is a property a
// grep can hold.
func auditUser(r *http.Request) string {
	claims, ok := callerClaims(r)
	if !ok || claims == nil || claims.Username == "" {
		return "system"
	}
	return claims.Username
}
