// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/router"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestStartUpWarnsOnceAboutRoutesThatCannotServe is OPS-N4: after an upgrade
// to v1.0.0's routes, those that now fail closed answered 503 and the one with
// a malformed rule matched nothing, and the start-up log said nothing about
// either -- the first sign was an ERROR when a request reached the route. One
// WARN at start now names them, and the dashboard's report drops a route once
// it is fixed.
func TestStartUpWarnsOnceAboutRoutesThatCannotServe(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	mustSave(t, mws.Update(ctx, &gateonv1.Middleware{Id: "jwt", Name: "jwt", Type: "auth"}))
	mustSave(t, routes.Update(ctx, &gateonv1.Route{Id: "callback", Name: "callback", Rule: "PathPrefix(`/cb`)", Middlewares: []string{"jwt"}}))
	mustSave(t, routes.Update(ctx, &gateonv1.Route{Id: "legacy", Name: "legacy", Rule: "Host(`a.example`"}))
	mustSave(t, routes.Update(ctx, &gateonv1.Route{Id: "fine", Name: "fine", Rule: "PathPrefix(`/`)"}))
	cache := NewProxyCache(routes, config.NewServiceRegistry(filepath.Join(dir, "services.json")), mws, nil,
		config.NewGlobalRegistry(filepath.Join(dir, "global.json")), nil, nil)
	t.Cleanup(cache.Purge)

	logs := captureLogs(t)
	cache.WarnRouteProblems(ctx)
	out := logs.String()
	if n := strings.Count(out, "routes that cannot serve as configured"); n != 1 {
		t.Fatalf("start-up warnings = %d, want one naming every route:\n%s", n, out)
	}
	for _, want := range []string{"callback (refuses)", "legacy (matches_nothing)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning does not name %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fine (") {
		t.Errorf("the warning names a route that serves:\n%s", out)
	}

	// Fixed and invalidated, the route leaves the report at once.
	mustSave(t, routes.Update(ctx, &gateonv1.Route{Id: "legacy", Name: "legacy", Rule: "Host(`a.example`)"}))
	cache.InvalidateRoute("legacy")
	for _, p := range cache.RouteProblems(ctx) {
		if p.RouteID == "legacy" {
			t.Fatalf("a fixed route is still reported: %+v", p)
		}
	}
	if got := cache.RouteProblems(ctx); len(got) != 1 || got[0].Kind != router.ProblemRefuses {
		t.Fatalf("report = %+v, want the refusing route alone", got)
	}
}
