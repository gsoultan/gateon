// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestHostMatches pins the routing decision. Over-matching here sends a request
// to a route it was not meant for, so the negative cases carry more weight than
// the positive ones.
func TestHostMatches(t *testing.T) {
	tests := []struct {
		name  string
		route string
		host  string
		want  bool
	}{
		{"an empty route host matches anything", "", "anything.example.com", true},
		{"exact", "example.com", "example.com", true},
		{"exact, case-insensitive", "example.com", "EXAMPLE.COM", true},
		{"exact, port stripped", "example.com", "example.com:8080", true},
		{"a different host does not match", "example.com", "other.com", false},

		{"wildcard matches one label", "*.example.com", "api.example.com", true},
		{"wildcard matches several labels", "*.example.com", "a.b.example.com", true},
		{"wildcard, case-insensitive", "*.example.com", "API.EXAMPLE.COM", true},
		{"wildcard, port stripped", "*.example.com", "api.example.com:443", true},

		// The one that matters. A suffix comparison without the leading dot
		// would match this, and an attacker who can register
		// evil-example.com would be served by the route for *.example.com.
		{"wildcard does not match a host that merely ends with the name",
			"*.example.com", "evil-example.com", false},
		{"wildcard does not match the apex", "*.example.com", "example.com", false},
		{"wildcard does not match a different domain", "*.example.com", "api.example.org", false},
		{"wildcard does not match a shorter host", "*.example.com", "com", false},

		{"IPv6 literal", "::1", "[::1]", true},
		// Regressed until 2026-09-04: the port and the brackets were stripped in
		// an if/else, so a bracketed literal kept its brackets whenever it
		// arrived with a port -- which is the ordinary case.
		{"IPv6 literal with a port", "::1", "[::1]:8080", true},
		{"IPv6 full form with a port", "2001:db8::1", "[2001:db8::1]:443", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostMatches(tt.route, tt.host); got != tt.want {
				t.Errorf("HostMatches(%q, %q) = %v, want %v", tt.route, tt.host, got, tt.want)
			}
		})
	}
}

// TestHostMatchesIgnoresTheDNSRootLabel replaces a note that used to record this
// as a known limitation.
//
// That note said the mismatch failed closed -- "the request finds no route
// rather than the wrong one" -- and asked for a reason before changing anything
// on the request path. The reason is that it does not always fail closed. A
// fully-qualified host misses its own host trie and misses a wildcard covering
// it, but an empty route host still matches everything, so the request falls
// through to any host-agnostic route the deployment has. A route carries its
// middleware chain, so that is the chain attached to the specific host being
// skipped, in the same way a path with dot segments skipped it.
//
// It only failed closed in a deployment where every single route was
// host-scoped.
func TestHostMatchesIgnoresTheDNSRootLabel(t *testing.T) {
	for _, tc := range []struct {
		rule, req string
		want      bool
	}{
		// The regression.
		{"app.example.com", "app.example.com.", true},
		{"app.example.com", "app.example.com.:8080", true},
		{"*.example.com", "app.example.com.", true},
		// An operator may write the FQDN in the rule too.
		{"app.example.com.", "app.example.com", true},
		{"app.example.com.", "app.example.com.", true},
		{"app.example.com", "APP.EXAMPLE.COM.", true},

		// What must still not match.
		{"app.example.com", "evil.example.com.", false},
		{"app.example.com", "app.example.com.evil.com", false},
		{"*.example.com", "example.com.evil.com", false},
	} {
		if got := HostMatches(tc.rule, tc.req); got != tc.want {
			t.Errorf("HostMatches(rule=%q, req=%q) = %v, want %v",
				tc.rule, tc.req, got, tc.want)
		}
	}
}

func TestRouteHostIsExact(t *testing.T) {
	tests := map[string]bool{
		"api.example.com": true,
		"example.com":     true,
		"*.example.com":   false,
		"*.EXAMPLE.COM":   false,
		"":                false,
		"*":               true, // not the "*." wildcard form
		"a*.example.com":  true, // a wildcard only counts as a leading "*."
	}
	for host, want := range tests {
		t.Run(host, func(t *testing.T) {
			if got := RouteHostIsExact(host); got != want {
				t.Errorf("RouteHostIsExact(%q) = %v, want %v", host, got, want)
			}
		})
	}
}

// TestNormalizeHost covers the key builder both sides use.
func TestNormalizeHost(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"app.example.com", "app.example.com"},
		{"app.example.com.", "app.example.com"},
		{"APP.Example.COM.", "app.example.com"},
		{"", ""},
		{".", "."}, // the bare root is not a host anyone routes to
	} {
		if got := NormalizeHost(tc.in); got != tc.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNormalizeHostDoesNotAllocateForOrdinaryHosts keeps the hot path honest.
//
// This runs per request through GetTrieByHost. An already-lower-case host with
// no root label is the common case and must cost nothing.
func TestNormalizeHostDoesNotAllocateForOrdinaryHosts(t *testing.T) {
	hosts := []string{"app.example.com", "api.internal", "localhost"}
	got := testing.AllocsPerRun(100, func() {
		for _, h := range hosts {
			_ = NormalizeHost(h)
		}
	})
	if got != 0 {
		t.Errorf("NormalizeHost allocated %v times per run on ordinary hosts, want 0", got)
	}
}

// TestRouteRegistryFindsFullyQualifiedHosts proves the two sides agree.
//
// HostMatches being right is not enough: the host trie is a map, and a request
// only reaches the matcher if the key built from the rule and the key built from
// the request are the same string. Normalising one and not the other just moves
// which spelling fails.
func TestRouteRegistryFindsFullyQualifiedHosts(t *testing.T) {
	reg := NewRouteRegistry(t.TempDir() + "/routes.json")
	if err := reg.Update(t.Context(), &gateonv1.Route{
		Id:   "admin",
		Rule: "Host(`app.example.com`) && PathPrefix(`/admin`)",
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	for _, host := range []string{
		"app.example.com",
		"app.example.com.", // the DNS root label
		"APP.EXAMPLE.COM",  // case
		"App.Example.Com.", // both
	} {
		trie, _ := reg.GetTrieByHost(host)
		if trie == nil {
			t.Errorf("GetTrieByHost(%q) found no trie; the route is indexed under a "+
				"different spelling of the same host, so the request skips every "+
				"host-scoped route and falls through to whatever is host-agnostic",
				host)
			continue
		}
		if got := trie.Lookup("/admin/users"); len(got) == 0 {
			t.Errorf("GetTrieByHost(%q) returned a trie with no candidates for "+
				"/admin/users", host)
		}
	}
}
