// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package router

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/transform"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RouteHasHostRule decides whether the unlisted-route detector treats a route
// as host-scoped: true only when every way the rule can match names a host. A
// rule with a branch that matches any host is not host-scoped, whatever its
// other branch says, and a misspelt Host is not a host rule.
func TestRouteHasHostRule(t *testing.T) {
	for rule, want := range map[string]bool{
		"Host(`app.example`)":                         true,
		"Host(`app.example`) && PathPrefix(`/api`)":   true,
		"PathPrefix(`/api`) || Host(`other.example`)": false, // the first branch matches any host
		"PathPrefix(`/api`)":                          false,
		"":                                            false,
		"Hots(`app.example`)":                         false, // a typo is not a host rule
	} {
		if got := RouteHasHostRule(rule); got != want {
			t.Errorf("RouteHasHostRule(%q) = %v, want %v", rule, got, want)
		}
	}
}

// RouteHasMiddlewareType decides whether a gRPC-Web request is handed to the
// route's own grpcweb middleware; a name that does not resolve, or resolves to
// another type, must not count.
func TestRouteHasMiddlewareType(t *testing.T) {
	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"gw":  {Id: "gw", Type: "GRPCWeb"},
		"hdr": {Id: "hdr", Type: "headers"},
	}}
	ctx := context.Background()
	cases := []struct {
		mws  []string
		typ  string
		want bool
	}{
		{[]string{"hdr", " gw "}, "grpcweb", true}, // trimmed id, case-insensitive type
		{[]string{"hdr"}, "grpcweb", false},
		{[]string{"missing", ""}, "grpcweb", false},
		{[]string{"gw"}, "", false},
	}
	for _, tc := range cases {
		rt := &gateonv1.Route{Middlewares: tc.mws}
		if got := RouteHasMiddlewareType(ctx, rt, store, tc.typ); got != tc.want {
			t.Errorf("RouteHasMiddlewareType(%v, %q) = %v, want %v", tc.mws, tc.typ, got, tc.want)
		}
	}
	if RouteHasMiddlewareType(ctx, &gateonv1.Route{Middlewares: []string{"gw"}}, nil, "grpcweb") {
		t.Error("a nil store answered true")
	}
}

// RouteReplacesBackendCORS decides whether the proxy strips the backend's CORS
// headers: only a gateway CORS policy that is not the "backend" preset, or
// gRPC-Web, replaces them. Stripping them under the backend preset would leave
// a route with no CORS answer at all.
func TestRouteReplacesBackendCORS(t *testing.T) {
	store := &stubMiddlewareStore{mws: map[string]*gateonv1.Middleware{
		"cors-own":     {Id: "cors-own", Type: "cors", Config: map[string]string{"allowed_origins": "https://a.example"}},
		"cors-backend": {Id: "cors-backend", Type: "cors", Config: map[string]string{"preset": transform.CORSPresetBackend}},
		"gw":           {Id: "gw", Type: "grpcweb"},
		"hdr":          {Id: "hdr", Type: "headers"},
	}}
	ctx := context.Background()
	for _, tc := range []struct {
		mws  []string
		want bool
	}{
		{[]string{"cors-own"}, true},
		{[]string{"cors-backend"}, false},
		{[]string{"gw"}, true},
		{[]string{"hdr", "missing"}, false},
	} {
		if got := RouteReplacesBackendCORS(ctx, &gateonv1.Route{Middlewares: tc.mws}, store); got != tc.want {
			t.Errorf("RouteReplacesBackendCORS(%v) = %v, want %v", tc.mws, got, tc.want)
		}
	}
	if RouteReplacesBackendCORS(ctx, &gateonv1.Route{Middlewares: []string{"cors-own"}}, nil) {
		t.Error("a nil store answered true")
	}
}
