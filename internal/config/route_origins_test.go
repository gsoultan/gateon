// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package config

import (
	"context"
	"slices"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type staticRouteStore struct{ routes []*gateonv1.Route }

func (s staticRouteStore) List(context.Context) []*gateonv1.Route { return s.routes }

func TestRouteOriginsTakesHostsFromRules(t *testing.T) {
	store := staticRouteStore{routes: []*gateonv1.Route{
		{Id: "a", Rule: "Host(`shop.example.com`) && PathPrefix(`/`)"},
		{Id: "b", Rule: "Host(`api.example.com`)"},
		{Id: "c", Rule: "Host(`shop.example.com`) && Path(`/cart`)"},
	}}

	got := RouteOrigins(context.Background(), store)
	if want := []string{"api.example.com", "shop.example.com"}; !slices.Equal(got, want) {
		t.Errorf("RouteOrigins = %v, want %v", got, want)
	}
}

// A wildcard is a matching pattern, not a name this gateway is reachable at.
//
// "Host(`*`)" is what a default catch-all route carries, and admitting it would
// hand the off-origin rules a literal "*" to compare destinations against. The
// rule would appear enabled in the dashboard and match nothing — the worst
// outcome available, because it looks like coverage.
func TestRouteOriginsRejectsWildcards(t *testing.T) {
	store := staticRouteStore{routes: []*gateonv1.Route{
		{Id: "catchall", Rule: "Host(`*`)"},
		{Id: "sub", Rule: "Host(`*.example.com`)"},
		{Id: "real", Rule: "Host(`app.example.com`)"},
	}}

	got := RouteOrigins(context.Background(), store)
	if want := []string{"app.example.com"}; !slices.Equal(got, want) {
		t.Errorf("RouteOrigins = %v, want %v — a wildcard is not an origin", got, want)
	}
}

// Path-only routes say what the gateway serves, not what it is called, so they
// contribute nothing and the result is empty rather than wrong.
func TestRouteOriginsIgnoresPathOnlyRoutes(t *testing.T) {
	store := staticRouteStore{routes: []*gateonv1.Route{
		{Id: "a", Rule: "PathPrefix(`/api`)"},
		{Id: "b", Rule: "Path(`/health`)"},
	}}

	if got := RouteOrigins(context.Background(), store); len(got) != 0 {
		t.Errorf("RouteOrigins = %v, want empty", got)
	}
}

func TestRouteOriginsHandlesNoStore(t *testing.T) {
	if got := RouteOrigins(context.Background(), nil); got != nil {
		t.Errorf("RouteOrigins(nil) = %v, want nil", got)
	}
}
