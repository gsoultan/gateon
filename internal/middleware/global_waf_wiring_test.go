// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The behaviour of the gateway-wide WAF is tested against NewGlobalWAF in
// internal/middleware/security. What only this side can check is the wiring:
// internal/router calls Factory.CreateGlobalWAF, and the factory is the piece
// that turns its own fields into a security.Deps. A field dropped from
// securityDeps compiles cleanly and produces a WAF built from a zero value --
// which, for GlobalStore, means a gateway with WAF enabled silently serving
// every route unprotected.
func TestCreateGlobalWAFPassesTheFactorysStoreThrough(t *testing.T) {
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, ParanoiaLevel: 1},
	}}
	f := NewFactory(nil, store, nil, nil, ".")

	if got := f.securityDeps().GlobalStore; got != store {
		t.Fatalf("securityDeps().GlobalStore = %v, want the factory's own store; "+
			"the global WAF would be built against a config it cannot read", got)
	}

	mw, err := f.CreateGlobalWAF()
	if err != nil {
		t.Fatalf("CreateGlobalWAF: %v", err)
	}
	if mw == nil {
		t.Fatal("CreateGlobalWAF returned nil with WAF enabled in the store it " +
			"was handed; the router would append nothing and every route would " +
			"run without the gateway-wide WAF")
	}
}

// TestCreateGlobalWAFPassesTheRouteTypeThrough guards the other field the
// gRPC relaxation reads. A route typed "grpc" gets transport relaxations that
// an HTTP route must not; if the factory stops forwarding RouteType, every
// route looks like HTTP and native gRPC traffic starts getting 403s.
func TestCreateGlobalWAFPassesTheRouteTypeThrough(t *testing.T) {
	f := NewFactory(nil, &mockGlobalConfigStore{}, nil, nil, ".")
	f.SetRouteType("grpc")

	if got := f.securityDeps().RouteType; got != "grpc" {
		t.Errorf("securityDeps().RouteType = %q, want %q", got, "grpc")
	}
}
