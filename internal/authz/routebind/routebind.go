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
// ADR 0072 adds the case that needs no repoint at all: a middleware that sends
// the request to a destination of its own (forward auth, OAuth2 introspection,
// wasm) placed after the credential on the same route, or reconfigured while it
// is. Binding one there, moving it after the credential, and changing its
// configuration while it sits on a credential route all need an administrator.
//
// The guard runs inside the domain SaveRoute/SaveService, which REST,
// Connect/gRPC and config-import all funnel through, so no transport is a way
// around it (mem:transport_rbac_bypass: authz that lived in one transport was
// reached around by another). It fails closed: a caller it cannot read as an
// administrator is treated as one who is not.
package routebind

import (
	"bytes"
	"context"
	"errors"
	"maps"
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
	"repointing a route that carries one, or sending such a route's requests to a middleware's own " +
	"destination, requires an administrator")

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
	if g.exposesCredentialToForwarder(ctx, stored, updated) {
		return ErrRequiresAdmin
	}
	return nil
}

// AuthorizeMiddlewareSave refuses a restricted caller who creates or changes a
// middleware that forwards the request to a destination of its own (see
// forwardsRequestOffRoute) while a route that carries a credential binds it
// (ADR 0072). Changing where forward auth sends the request, or what a wasm
// guest does with it, is the same capture as binding a new one: the credential
// the route sets reaches whatever the configuration now names. It runs after
// the stored secrets are restored, so a placeholder sent back compares equal
// to what it stands for. A save that leaves type, config and module untouched
// (a rename) is allowed.
func (g *Guard) AuthorizeMiddlewareSave(ctx context.Context, updated *gateonv1.Middleware) error {
	if g == nil || updated == nil || !g.restricted(ctx) || !forwardsRequestOffRoute(updated) {
		return nil
	}
	id := strings.TrimSpace(updated.GetId())
	if id == "" {
		return nil // a fresh id is assigned after this; no route can name it yet
	}
	if stored, ok := g.mws.Get(ctx, id); ok && sameForwarding(stored, updated) {
		return nil
	}
	// A stored middleware is not required: a route may already name an id that
	// has no middleware yet, and creating it under that id is the binding.
	for _, rt := range g.routes.List(ctx) {
		if slices.Contains(trimmedIDs(rt), id) && g.routeCarriesCredential(ctx, rt) {
			return ErrRequiresAdmin
		}
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

// exposesCredentialToForwarder reports whether updated puts a middleware that
// forwards the request off the route after a credential-injecting one, where
// stored did not already run that forwarder after that credential. Order is
// what matters: a forwarder that runs first has not seen the credential yet, so
// moving it later is as much a capture as adding it. A pair the stored route
// already had is an existing (admin-made) binding the caller kept.
func (g *Guard) exposesCredentialToForwarder(ctx context.Context, stored, updated *gateonv1.Route) bool {
	before := trimmedIDs(stored)
	var sawCredential []string
	for _, id := range trimmedIDs(updated) {
		mw, ok := g.mws.Get(ctx, id)
		if !ok {
			continue
		}
		if mwsecret.InjectsCredentialUpstream(mw) {
			sawCredential = append(sawCredential, id)
			continue
		}
		if !forwardsRequestOffRoute(mw) {
			continue
		}
		for _, cred := range sawCredential {
			if !runsBefore(before, cred, id) {
				return true
			}
		}
	}
	return false
}

// runsBefore reports whether some occurrence of first precedes some occurrence
// of second in ids.
func runsBefore(ids []string, first, second string) bool {
	i := slices.Index(ids, first)
	if i < 0 {
		return false
	}
	return slices.Contains(ids[i+1:], second)
}

// forwardsRequestOffRoute reports whether mw sends the request, or the
// credential on it, somewhere other than the route's backend -- to a
// destination its own configuration chooses. Forward auth copies the request
// headers to its address (all of them when auth_request_headers is empty);
// OAuth2 introspection posts the request's bearer token to its
// introspection_url; a wasm guest reads any request header and can carry it
// out through what it records. Each of these, run after a credential-injecting
// middleware, delivers the credential to wherever it is configured to send,
// with no repoint of the route or its service (ADR 0072).
//
// Not included: the JWT and OIDC validators fetch keys from their issuer but
// send it nothing from the request; the oidc proxy sends its own client secret,
// which ADR 0034 already binds to its issuer.
func forwardsRequestOffRoute(mw *gateonv1.Middleware) bool {
	switch strings.ToLower(strings.TrimSpace(mw.GetType())) {
	case "forwardauth", "wasm":
		return true
	case "auth":
		switch strings.ToLower(strings.TrimSpace(mw.GetConfig()["type"])) {
		case "oauth2", "oauth2_introspection":
			return true
		}
	}
	return false
}

// sameForwarding reports whether updated forwards exactly as stored does: the
// same type, configuration and wasm module. The name is not compared.
func sameForwarding(stored, updated *gateonv1.Middleware) bool {
	return stored != nil &&
		strings.TrimSpace(stored.GetType()) == strings.TrimSpace(updated.GetType()) &&
		maps.Equal(stored.GetConfig(), updated.GetConfig()) &&
		bytes.Equal(stored.GetWasmBlob(), updated.GetWasmBlob())
}

// trimmedIDs is rt's middleware ids in order, blanks dropped; empty for a nil
// route.
func trimmedIDs(rt *gateonv1.Route) []string {
	ids := make([]string, 0, len(rt.GetMiddlewares()))
	for _, id := range rt.GetMiddlewares() {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
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
