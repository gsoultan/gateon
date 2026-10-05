// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/config/mwsecret"
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

// TestRouteProblemsDropARouteWhoseRefusalRecovered is review-3 F4: a route
// refused because its $env: secret was unreadable at start was reported
// "refuses", which is right; once the secret was readable the router's retry
// rebuilt the chain and the route served, but the report was cached by
// invalidation epoch, which a retry does not move, so the dashboard kept
// calling the route refused until some unrelated configuration changed.
func TestRouteProblemsDropARouteWhoseRefusalRecovered(t *testing.T) {
	f, rt, makeReadable := refusedOnUnreadableSecret(t)
	if got := f.cache.RouteProblems(t.Context()); len(got) != 1 || got[0].RouteID != "r1" || got[0].Kind != router.ProblemRefuses {
		t.Fatalf("report = %+v, want r1 refusing", got)
	}
	makeReadable()
	if code := serveThrough(f.cache.GetOrCreate(rt)).Code; code == http.StatusServiceUnavailable {
		t.Fatal("with the secret readable the retried route still answered 503")
	}
	if got := f.cache.RouteProblems(t.Context()); len(got) != 0 {
		t.Fatalf("report = %+v after the route recovered, want none", got)
	}
}

// TestRouteProblemsAreRebuiltOnlyForARecovery holds the F4 fix to its cost:
// the report is invalidated when a refused chain is replaced by one that
// serves, and not by the request path's cache hits or by a retry that is
// refused again, so a polled dashboard still does not rebuild every route's
// middlewares for nothing.
func TestRouteProblemsAreRebuiltOnlyForARecovery(t *testing.T) {
	f, rt, makeReadable := refusedOnUnreadableSecret(t)
	serveThrough(f.cache.GetOrCreate(rt)) // retried, refused again
	if n := f.cache.recovered.Load(); n != 0 {
		t.Fatalf("a retry refused again counted as %d recoveries", n)
	}
	makeReadable()
	serveThrough(f.cache.GetOrCreate(rt)) // retried, serves
	serveThrough(f.cache.GetOrCreate(rt)) // a cache hit
	if n := f.cache.recovered.Load(); n != 1 {
		t.Fatalf("recoveries = %d after one recovery and a cache hit, want 1", n)
	}
}

// refusedOnUnreadableSecret is a cache with route r1 behind a jwt middleware
// whose $env: secret is unset, served once (503) and retried on every request.
// makeReadable makes the secret readable.
func refusedOnUnreadableSecret(t *testing.T) (f *cacheFixture, rt *gateonv1.Route, makeReadable func()) {
	t.Helper()
	f, release := newCacheFixture(t, "none")
	release()
	t.Cleanup(f.cache.Purge)
	const secretEnv = "GATEON_TEST_F4_JWT_SECRET"
	t.Setenv(mwsecret.SecretRefsEnv, "$env:"+secretEnv)
	t.Setenv(secretEnv, "")
	mustSave(t, f.mws.Update(t.Context(), &gateonv1.Middleware{Id: "jwt", Name: "jwt", Type: "auth",
		Config: map[string]string{"type": "jwt", "secret": "$env:" + secretEnv}}))
	rt = f.route(t, "r1", "jwt")
	f.cache.refusalRetry = time.Nanosecond
	if code := serveThrough(f.cache.GetOrCreate(rt)).Code; code != http.StatusServiceUnavailable {
		t.Fatalf("with the secret unreadable the route answered %d, want 503", code)
	}
	return f, rt, func() { t.Setenv(secretEnv, "0123456789abcdef0123456789abcdef") }
}
