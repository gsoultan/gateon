// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package routebind

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	mwauth "github.com/gsoultan/gateon/internal/middleware/auth"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func newGuard(t *testing.T) (*Guard, *config.RouteRegistry, *config.ServiceRegistry, *config.MiddlewareRegistry) {
	t.Helper()
	dir := t.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "r.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "s.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "m.json"))
	ctx := context.Background()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(mws.Update(ctx, &gateonv1.Middleware{Id: "cred", Type: "headers",
		Config: map[string]string{"set_request_Authorization": "Bearer s"}}))
	must(mws.Update(ctx, &gateonv1.Middleware{Id: "plain", Type: "headers",
		Config: map[string]string{"set_request_X-Trace": "t"}}))
	must(services.Update(ctx, &gateonv1.Service{Id: "svc-a",
		WeightedTargets: []*gateonv1.Target{{Url: "http://a:1"}}}))
	must(services.Update(ctx, &gateonv1.Service{Id: "svc-b",
		WeightedTargets: []*gateonv1.Target{{Url: "http://b:2"}}}))
	return NewGuard(routes, services, mws), routes, services, mws
}

func asRole(role string) context.Context {
	return context.WithValue(context.Background(), mwauth.UserContextKey, &auth.Claims{Role: role})
}

func rt(id, svc string, mws ...string) *gateonv1.Route {
	return &gateonv1.Route{Id: id, Type: "http", Rule: "Host(`x`)", ServiceId: svc, Middlewares: mws}
}

func TestAuthorizeRouteSave_Operator(t *testing.T) {
	g, routes, _, _ := newGuard(t)
	op := asRole(auth.RoleOperator)

	if err := g.AuthorizeRouteSave(op, rt("new", "svc-b", "cred")); !errors.Is(err, ErrRequiresAdmin) {
		t.Fatalf("operator binding a credential middleware: got %v, want ErrRequiresAdmin", err)
	}
	if err := g.AuthorizeRouteSave(op, rt("ord", "svc-a", "plain")); err != nil {
		t.Fatalf("operator on an ordinary route: got %v, want nil", err)
	}

	// A stored admin binding kept unchanged is allowed; repointing it is not.
	_ = routes.Update(context.Background(), rt("stored", "svc-a", "cred"))
	if err := g.AuthorizeRouteSave(op, rt("stored", "svc-a", "cred")); err != nil {
		t.Fatalf("operator keeping an admin binding: got %v, want nil", err)
	}
	if err := g.AuthorizeRouteSave(op, rt("stored", "svc-b", "cred")); !errors.Is(err, ErrRequiresAdmin) {
		t.Fatalf("operator repointing a credential route: got %v, want ErrRequiresAdmin", err)
	}
}

func TestAuthorizeRouteSave_AdminAndAuthOff(t *testing.T) {
	g, _, _, _ := newGuard(t)
	if err := g.AuthorizeRouteSave(asRole(auth.RoleAdmin), rt("a", "svc-b", "cred")); err != nil {
		t.Fatalf("admin binding a credential middleware: got %v, want nil", err)
	}
	// No claims on the context means authentication is off: no role distinction,
	// so the guard does not restrict.
	if err := g.AuthorizeRouteSave(context.Background(), rt("a", "svc-b", "cred")); err != nil {
		t.Fatalf("auth-off save: got %v, want nil", err)
	}
}

func TestAuthorizeRouteSave_UnreadableClaimsFailClosed(t *testing.T) {
	g, _, _, _ := newGuard(t)
	// A claims value present but not *auth.Claims establishes nothing about the
	// caller; the guard must treat it as a non-admin and refuse the binding.
	ctx := context.WithValue(context.Background(), mwauth.UserContextKey, "not-claims")
	if err := g.AuthorizeRouteSave(ctx, rt("a", "svc-b", "cred")); !errors.Is(err, ErrRequiresAdmin) {
		t.Fatalf("unreadable claims binding a credential middleware: got %v, want ErrRequiresAdmin", err)
	}
}

func TestAuthorizeServiceSave_Repoint(t *testing.T) {
	g, routes, _, _ := newGuard(t)
	_ = routes.Update(context.Background(), rt("stored", "svc-a", "cred"))
	op := asRole(auth.RoleOperator)

	// Repointing svc-a, which a credential route depends on, is refused.
	moved := &gateonv1.Service{Id: "svc-a", WeightedTargets: []*gateonv1.Target{{Url: "http://evil:9"}}}
	if err := g.AuthorizeServiceSave(op, moved); !errors.Is(err, ErrRequiresAdmin) {
		t.Fatalf("operator repointing a credential-backed service: got %v, want ErrRequiresAdmin", err)
	}
	// The same targets (no repoint) is allowed even for a credential-backed service.
	same := &gateonv1.Service{Id: "svc-a", Name: "renamed", WeightedTargets: []*gateonv1.Target{{Url: "http://a:1"}}}
	if err := g.AuthorizeServiceSave(op, same); err != nil {
		t.Fatalf("operator editing a service without repointing: got %v, want nil", err)
	}
	// A service no credential route depends on may be repointed.
	freeMove := &gateonv1.Service{Id: "svc-b", WeightedTargets: []*gateonv1.Target{{Url: "http://c:3"}}}
	if err := g.AuthorizeServiceSave(op, freeMove); err != nil {
		t.Fatalf("operator repointing an unreferenced service: got %v, want nil", err)
	}
}

func TestNilGuardAllows(t *testing.T) {
	var g *Guard
	if err := g.AuthorizeRouteSave(asRole(auth.RoleOperator), rt("a", "svc-b", "cred")); err != nil {
		t.Fatalf("nil guard AuthorizeRouteSave: got %v, want nil", err)
	}
	if err := g.AuthorizeServiceSave(asRole(auth.RoleOperator), &gateonv1.Service{Id: "svc-a"}); err != nil {
		t.Fatalf("nil guard AuthorizeServiceSave: got %v, want nil", err)
	}
}
