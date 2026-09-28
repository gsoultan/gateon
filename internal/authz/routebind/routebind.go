// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package routebind decides whether a route or service save is allowed to bind a
// middleware that injects a credential toward the backend. ADR 0033 left this as
// residue: the headers and rewrite middlewares deliver what they set to whatever
// backend the route using them points at, and an operator (role operator, not
// admin) may write both routes and services. So an operator could attach an
// existing, admin-configured credential-injecting middleware to a route whose
// service targets a backend they run, and read the stored Authorization or
// X-Api-Key value at their own server -- an operator-to-admin escalation, even
// though middleware secrets are write-only (ADR 0033) and references are
// host-gated (ADR 0034).
//
// The rule (ADR 0038): only an administrator may create or change a route in a
// way that newly binds a credential-injecting middleware to it, or repoint a
// route -- or the service it targets -- that already carries one to a different
// backend. An operator keeps every other power: ordinary routes, and an
// existing admin-made binding left untouched.
//
// The guard runs inside the domain SaveRoute/SaveService, which REST,
// Connect/gRPC and config-import all funnel through, so no transport is a way
// around it (mem:transport_rbac_bypass: authz that lived in one transport was
// reached around by another). It fails closed: a caller it cannot read as an
// administrator is treated as one who is not.
package routebind

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/config/mwsecret"
	mwauth "github.com/gsoultan/gateon/internal/middleware/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ErrRequiresAdmin refuses a non-admin save that would newly bind, or repoint,
// a credential-injecting middleware. Handlers map it to 403 / PermissionDenied.
var ErrRequiresAdmin = errors.New("binding a middleware that injects a credential toward the backend, " +
	"or repointing a route that carries one, requires an administrator")

// Guard resolves the middlewares a route binds and the routes a service backs,
// so it can tell an ordinary save from one that moves a credential toward a
// backend the caller may control.
type Guard struct {
	routes   config.RouteStore
	services config.ServiceStore
	mws      config.MiddlewareStore
}

// NewGuard builds a Guard over the stores it reads. All three are required; a
// nil store would make the guard silently allow, which is the failure it exists
// to prevent.
func NewGuard(routes config.RouteStore, services config.ServiceStore, mws config.MiddlewareStore) *Guard {
	return &Guard{routes: routes, services: services, mws: mws}
}

// AuthorizeRouteSave refuses a restricted caller who newly binds a
// credential-injecting middleware to updated, or repoints an updated route that
// carries one to a different service. A nil guard, an unrestricted caller (an
// administrator, or auth turned off) and an ordinary route all return nil.
func (g *Guard) AuthorizeRouteSave(ctx context.Context, updated *gateonv1.Route) error {
	if g == nil || updated == nil || !g.restricted(ctx) {
		return nil
	}
	stored := g.storedRoute(ctx, updated.GetId())
	if g.newlyBindsCredential(ctx, stored, updated) {
		return ErrRequiresAdmin
	}
	if g.repointsCredentialRoute(ctx, stored, updated) {
		return ErrRequiresAdmin
	}
	return nil
}

// AuthorizeServiceSave refuses a restricted caller who repoints an existing
// service (changes its targets or discovery URL) that any credential-carrying
// route depends on -- the other end of the same escalation, reached by moving
// the backend under a route the caller left alone.
func (g *Guard) AuthorizeServiceSave(ctx context.Context, updated *gateonv1.Service) error {
	if g == nil || updated == nil || !g.restricted(ctx) {
		return nil
	}
	stored, ok := g.services.Get(ctx, updated.GetId())
	if !ok || stored == nil {
		// A new service has a fresh id no route can reference yet, so it cannot
		// be a repoint. Binding it to a credential-carrying route happens on the
		// route save, which AuthorizeRouteSave covers.
		return nil
	}
	if !targetsChanged(stored, updated) {
		return nil
	}
	for _, rt := range g.routes.List(ctx) {
		if rt.GetServiceId() == updated.GetId() && g.routeCarriesCredential(ctx, rt) {
			return ErrRequiresAdmin
		}
	}
	return nil
}

// restricted reports whether the caller must be held to the admin-only rule.
// Fails closed: a claims value present but not readable as *auth.Claims is
// treated as a non-admin, because it establishes nothing about who is calling.
func (g *Guard) restricted(ctx context.Context) bool {
	v := ctx.Value(mwauth.UserContextKey)
	if v == nil {
		// No claims at all means authentication is off for the deployment; there
		// is no operator/admin distinction to enforce, and the management plane
		// is open by configuration. RequirePermission admits the same case.
		return false
	}
	claims, ok := v.(*auth.Claims)
	if ok && claims != nil && claims.Role == auth.RoleAdmin {
		return false
	}
	return true
}

func (g *Guard) storedRoute(ctx context.Context, id string) *gateonv1.Route {
	if id == "" {
		return nil
	}
	rt, ok := g.routes.Get(ctx, id)
	if !ok {
		return nil
	}
	return rt
}

// newlyBindsCredential reports whether updated binds a credential-injecting
// middleware that stored did not already bind. An id present on both is an
// existing binding the caller kept, which is allowed.
func (g *Guard) newlyBindsCredential(ctx context.Context, stored, updated *gateonv1.Route) bool {
	kept := middlewareSet(stored)
	for _, id := range updated.GetMiddlewares() {
		id = strings.TrimSpace(id)
		if id == "" || kept[id] {
			continue
		}
		if mw, ok := g.mws.Get(ctx, id); ok && mwsecret.InjectsCredentialUpstream(mw) {
			return true
		}
	}
	return false
}

// repointsCredentialRoute reports whether updated carries a credential-injecting
// middleware and points at a different service than stored did.
func (g *Guard) repointsCredentialRoute(ctx context.Context, stored, updated *gateonv1.Route) bool {
	if stored == nil || stored.GetServiceId() == updated.GetServiceId() {
		return false
	}
	return g.routeCarriesCredential(ctx, updated)
}

// routeCarriesCredential reports whether any middleware rt binds injects a
// credential toward the backend.
func (g *Guard) routeCarriesCredential(ctx context.Context, rt *gateonv1.Route) bool {
	for _, id := range rt.GetMiddlewares() {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if mw, ok := g.mws.Get(ctx, id); ok && mwsecret.InjectsCredentialUpstream(mw) {
			return true
		}
	}
	return false
}

func middlewareSet(rt *gateonv1.Route) map[string]bool {
	if rt == nil {
		return nil
	}
	set := make(map[string]bool, len(rt.GetMiddlewares()))
	for _, id := range rt.GetMiddlewares() {
		if id = strings.TrimSpace(id); id != "" {
			set[id] = true
		}
	}
	return set
}

// targetsChanged reports whether the set of backend targets, or the discovery
// URL, differs between the stored service and the update. Order is not identity
// -- weighted targets are a set -- so the URLs are compared sorted.
func targetsChanged(stored, updated *gateonv1.Service) bool {
	if strings.TrimSpace(stored.GetDiscoveryUrl()) != strings.TrimSpace(updated.GetDiscoveryUrl()) {
		return true
	}
	return !slices.Equal(targetURLs(stored), targetURLs(updated))
}

func targetURLs(svc *gateonv1.Service) []string {
	urls := make([]string, 0, len(svc.GetWeightedTargets()))
	for _, t := range svc.GetWeightedTargets() {
		urls = append(urls, strings.TrimSpace(t.GetUrl()))
	}
	slices.Sort(urls)
	return urls
}
