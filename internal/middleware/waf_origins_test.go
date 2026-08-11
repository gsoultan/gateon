// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"slices"
	"testing"
)

// Origins are what the off-origin redirect and SSRF rules compare a destination
// against. gwaf v0.4.1 stopped reading the Host header for this because the
// attacker writes it as freely as the destination being judged, so everything
// here has to come from configuration and nothing may come from a request.

func TestResolveOriginsMergesDeclaredAndRouteDerived(t *testing.T) {
	SetRouteOriginProvider(func() []string { return []string{"api.example.com", "shop.example.com"} })
	t.Cleanup(func() { SetRouteOriginProvider(nil) })

	got := resolveOrigins([]string{"admin.example.com"})
	want := []string{"admin.example.com", "api.example.com", "shop.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("resolveOrigins = %v, want %v", got, want)
	}
}

// Sorted and de-duplicated, because the routing table's order is not meaningful
// and a gateway routinely has several routes on one host. Without this the
// config fingerprint would churn and rebuild every engine for no reason.
func TestResolveOriginsIsStableAndDeduplicated(t *testing.T) {
	SetRouteOriginProvider(func() []string { return []string{"b.example.com", "a.example.com", "a.example.com"} })
	t.Cleanup(func() { SetRouteOriginProvider(nil) })

	first := resolveOrigins([]string{"a.example.com"})
	second := resolveOrigins([]string{"a.example.com"})

	if !slices.Equal(first, second) {
		t.Errorf("not stable across calls: %v then %v", first, second)
	}
	if want := []string{"a.example.com", "b.example.com"}; !slices.Equal(first, want) {
		t.Errorf("resolveOrigins = %v, want %v", first, want)
	}
}

func TestResolveOriginsNormalisesCaseAndPort(t *testing.T) {
	SetRouteOriginProvider(nil)

	got := resolveOrigins([]string{"  APP.Example.com:8443 ", "app.example.com"})
	if want := []string{"app.example.com"}; !slices.Equal(got, want) {
		t.Errorf("resolveOrigins = %v, want %v — case and port must not split one origin into two", got, want)
	}
}

// The empty case is a real state, not a bug: an install with only path-matched
// routes and no declared origins has nothing trustworthy to compare against, and
// the rules stay quiet rather than guess. newWAFEngine logs when this happens.
func TestResolveOriginsIsEmptyWhenNothingIsDeclared(t *testing.T) {
	SetRouteOriginProvider(nil)

	if got := resolveOrigins(nil); len(got) != 0 {
		t.Errorf("resolveOrigins = %v, want empty", got)
	}
}

// A provider that panics or is absent must not take the request path with it.
func TestResolveOriginsSurvivesAnAbsentProvider(t *testing.T) {
	SetRouteOriginProvider(nil)

	if got := resolveOrigins([]string{"app.example.com"}); !slices.Equal(got, []string{"app.example.com"}) {
		t.Errorf("resolveOrigins = %v, want the declared origin", got)
	}
}
