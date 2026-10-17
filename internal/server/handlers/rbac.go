// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
)

// RequirePermission checks that the request has a valid user with permission for the action on resource.
// A request with no claims is allowed only when the base handler marked it as
// needing none (authentication off for the deployment; see
// middleware.AuthNotRequired); otherwise it is refused as unauthenticated.
// Returns false if refused.
func RequirePermission(w http.ResponseWriter, r *http.Request, action auth.Action, resource auth.Resource) bool {
	logger.L.LogDebug("checking permission", "path", r.URL.Path, "action", action, "resource", resource)
	claimsVal := r.Context().Value(middleware.UserContextKey)
	if claimsVal == nil {
		if middleware.AuthNotRequired(r.Context()) {
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"authentication required"}`))
		return false
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
		// Nobody, which is acceptable only where the base handler said nobody
		// is needed (auth off, or a path that works before a session exists).
		return nil, middleware.AuthNotRequired(r.Context())
	}
	claims, isClaims := v.(*auth.Claims)
	if !isClaims || claims == nil {
		return nil, false
	}
	return claims, true
}

// callerOrSelfAuthenticated is callerClaims for a handler that verifies a
// credential of its own when no claims arrived -- the log stream accepts its
// token in the query string, which a WebSocket needs. For such a handler "no
// claims" is not a refusal but a cue to authenticate, so it is (nil, true)
// whether or not the base handler waived authentication; the handler then
// denies unless its own verification succeeds. An unreadable claims value is
// still (nil, false).
func callerOrSelfAuthenticated(r *http.Request) (*auth.Claims, bool) {
	if r.Context().Value(middleware.UserContextKey) == nil {
		return nil, true
	}
	return callerClaims(r)
}

// callerMayWrite reports whether the caller holds ActionWrite on resource,
// without writing a response. It is for a handler that serves a read to every
// caller RequirePermission admits but shapes the payload by what the caller
// could change: a role that cannot write a configuration has no use for the
// credentials in it. The three states follow callerClaims -- no claims means
// auth is disabled and the read is unrestricted; an unreadable claims value
// establishes nothing and gets the restricted view.
func callerMayWrite(r *http.Request, resource auth.Resource) bool {
	claims, ok := callerClaims(r)
	if !ok {
		return false
	}
	if claims == nil {
		return true
	}
	return auth.Allowed(r.Context(), claims.Role, auth.ActionWrite, resource)
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

// streamRecheckEvery is how often an open management stream asks again whether
// its caller may still read it: the session binding's cache TTL
// (auth.DefaultBindingTTL), so a stream outlives a sign-out, a disable or a
// demotion by at most one interval more than a request made after it would.
const streamRecheckEvery = 30 * time.Second

// streamPermission is what a management stream needs to go on.
type streamPermission struct {
	action   auth.Action
	resource auth.Resource
}

// diagnosticsRead is the permission every management stream is opened under:
// the system log and the live events are read-only observability.
var diagnosticsRead = streamPermission{action: auth.ActionRead, resource: auth.ResourceDiagnostics}

// streamGrant is what a management stream was opened under: the session token
// that authorized it, and the permission it needs to go on.
type streamGrant struct {
	verifier auth.Service
	token    string
	perm     streamPermission
}

// holds re-runs the check the stream was opened under -- the token through the
// same VerifyToken every request takes, which compares the session binding
// (password, role, disabled flag, sign-out epoch; ADR 0005, 0012) and the
// expiry, then the role against the permission, which reads the RBAC policy in
// force now. It returns the claims when they still hold.
func (g streamGrant) holds(ctx context.Context) (*auth.Claims, bool) {
	if g.token == "" || !auth.Available(g.verifier) {
		return nil, false
	}
	raw, err := g.verifier.VerifyToken(g.token)
	if err != nil {
		return nil, false
	}
	claims, isClaims := raw.(*auth.Claims)
	if !isClaims || claims == nil {
		return nil, false
	}
	return claims, auth.Allowed(ctx, claims.Role, g.perm.action, g.perm.resource)
}

// streamGuard is what keeps a management stream to its caller's session. A
// stream was authorized once, when it opened, and then ran until its client
// left or the stream lifetime cap (up to 12h, past the 8h token lifetime)
// ended it, so signing out, disabling the account or demoting it left every
// open log and event stream running (ADR 0077). Its watch ends the stream when
// the token expires, and when a re-check every streamRecheckEvery finds the
// caller no longer holds the permission.
//
// It is nil for a stream opened with no caller, where the base handler waived
// authentication for the deployment: there is no session to lose.
func (d *Deps) streamGuard(r *http.Request, p streamPermission) *streamRecheck {
	if claims, ok := callerClaims(r); ok && claims == nil {
		return nil
	}
	return &streamRecheck{
		grant: streamGrant{verifier: d.AuthManager, token: middleware.ExtractToken(r), perm: p},
		clock: d.newStreamTicker,
	}
}

// streamRecheck is one stream's re-check: the grant it re-checks and the clock
// it re-checks by.
type streamRecheck struct {
	grant  streamGrant
	clock  func() (<-chan time.Time, func())
	cancel context.CancelFunc
}

// watch ends the stream through cancel -- at once when the grant does not
// hold now, else at the token's expiry or the first re-check on which it no
// longer holds -- and stops watching when ctx ends. A nil guard watches
// nothing.
func (s *streamRecheck) watch(ctx context.Context, cancel context.CancelFunc) {
	if s == nil {
		return
	}
	claims, ok := s.grant.holds(ctx)
	if !ok {
		cancel()
		return
	}
	s.cancel = cancel
	ticks, stop := s.clock()
	expiry := expiryTimer(claims.Expiration)
	go func() {
		defer stop()
		defer expiry.Stop()
		s.run(ctx, ticks, expiry.C)
	}()
}

// run is the watch loop: it cancels the stream at expired or at the first tick
// on which the grant no longer holds, and returns when ctx ends either way.
func (s *streamRecheck) run(ctx context.Context, ticks <-chan time.Time, expired <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-expired:
			s.cancel()
			return
		case <-ticks:
			if _, ok := s.grant.holds(ctx); !ok {
				s.cancel()
				return
			}
		}
	}
}

// expiryTimer fires when a token expiring at exp does; a token that states no
// expiry gets a timer that never fires.
func expiryTimer(exp time.Time) *time.Timer {
	if exp.IsZero() {
		t := time.NewTimer(time.Hour)
		t.Stop()
		return t
	}
	return time.NewTimer(time.Until(exp))
}

// newStreamTicker is the clock a stream re-checks by: every
// streamRecheckEvery, unless a test gave Deps a clock of its own.
func (d *Deps) newStreamTicker() (<-chan time.Time, func()) {
	if d.streamTicks != nil {
		return d.streamTicks()
	}
	t := time.NewTicker(streamRecheckEvery)
	return t.C, t.Stop
}
