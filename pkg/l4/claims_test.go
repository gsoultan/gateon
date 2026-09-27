// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// claimsFixture is a resolver over registries holding a tcp route on
// entrypoint "ep", and the registry, so a test can add routes beside it.
func claimsFixture(t *testing.T) (*Resolver, *config.RouteRegistry) {
	t.Helper()
	dir := t.TempDir()
	routes := config.NewRouteRegistry(filepath.Join(dir, "routes.json"))
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	ctx := context.Background()
	svc := &gateonv1.Service{Id: "svc", BackendType: "tcp", WeightedTargets: []*gateonv1.Target{{Url: "tcp://127.0.0.1:1"}}}
	if services.Update(ctx, svc) != nil ||
		routes.Update(ctx, &gateonv1.Route{Id: "tcp", Type: "tcp", Entrypoints: []string{"ep"}, ServiceId: "svc"}) != nil {
		t.Fatal("could not store the fixture")
	}
	return NewResolver(routes, services), routes
}

// TestOnlyTCPRouteIsTheRouteOfAnEntrypointThatServesNothingElse: an entrypoint
// skips detection -- and so its window -- only when nothing but its tcp route
// can claim a connection there. An HTTP-served route that lists no entrypoint
// is served on all of them, so it makes every entrypoint one to inspect.
func TestOnlyTCPRouteIsTheRouteOfAnEntrypointThatServesNothingElse(t *testing.T) {
	cases := []struct {
		name  string
		also  *gateonv1.Route
		alone bool
	}{
		{"only the tcp route", nil, true},
		{"an HTTP route lists the entrypoint", &gateonv1.Route{Type: "http", Entrypoints: []string{"ep"}}, false},
		{"an HTTP route lists no entrypoint", &gateonv1.Route{Type: "http"}, false},
		{"a gRPC route lists the entrypoint", &gateonv1.Route{Type: "grpc", Entrypoints: []string{"ep"}}, false},
		{"an ssh route lists the entrypoint", &gateonv1.Route{Type: "ssh", Entrypoints: []string{"ep"}, ServiceId: "svc"}, false},
		{"an HTTP route lists another entrypoint", &gateonv1.Route{Type: "http", Entrypoints: []string{"other"}}, true},
		{"a disabled HTTP route lists the entrypoint", &gateonv1.Route{Type: "http", Entrypoints: []string{"ep"}, Disabled: true}, true},
		{"a udp route lists the entrypoint", &gateonv1.Route{Type: "udp", Entrypoints: []string{"ep"}, ServiceId: "svc"}, true},
		{"an ssh route with no service lists it", &gateonv1.Route{Type: "ssh", Entrypoints: []string{"ep"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, routes := claimsFixture(t)
			if tc.also != nil {
				tc.also.Id = "also"
				if routes.Update(context.Background(), tc.also) != nil {
					t.Fatal("could not store the route")
				}
			}
			if got := r.OnlyTCPRoute(&gateonv1.EntryPoint{Id: "ep"}) != nil; got != tc.alone {
				t.Errorf("OnlyTCPRoute answered %v, want %v", got, tc.alone)
			}
		})
	}
	r, _ := claimsFixture(t)
	if r.OnlyTCPRoute(&gateonv1.EntryPoint{Id: "no-routes"}) != nil {
		t.Error("an entrypoint with no tcp route was given one")
	}
}

// TestOnlyTCPRouteFollowsRouteChangesWithoutBeingTold: the answer is cached,
// and no invalidation reaches the cache -- the resolver's hooks are not even
// called when a route is deleted -- so it must notice a change by itself. An
// HTTP route added beside the tcp route must end the fast path at once, or
// its requests would be spliced to the tcp backend; removed, it must restore it.
func TestOnlyTCPRouteFollowsRouteChangesWithoutBeingTold(t *testing.T) {
	r, routes := claimsFixture(t)
	ep := &gateonv1.EntryPoint{Id: "ep"}
	if r.OnlyTCPRoute(ep) == nil {
		t.Fatal("a tcp-only entrypoint was not recognised")
	}
	web := &gateonv1.Route{Id: "web", Type: "http", Entrypoints: []string{"ep"}}
	if routes.Update(context.Background(), web) != nil {
		t.Fatal("could not store the HTTP route")
	}
	if r.OnlyTCPRoute(ep) != nil {
		t.Fatal("after an HTTP route was added to it, the entrypoint still skipped detection")
	}
	if routes.Delete(context.Background(), "web") != nil {
		t.Fatal("could not delete the HTTP route")
	}
	if r.OnlyTCPRoute(ep) == nil {
		t.Error("after its HTTP route was deleted, the entrypoint still inspected")
	}
}
