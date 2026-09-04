// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import "testing"

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

// TestHostMatchesTrailingDot records a known limitation rather than asserting a
// fix. "example.com." is the fully qualified form and some clients send it; it
// does not match a route for "example.com". That fails closed -- the request
// finds no route rather than the wrong one -- so it is documented here instead
// of being changed on the request path without a reason to.
func TestHostMatchesTrailingDot(t *testing.T) {
	if HostMatches("example.com", "example.com.") {
		t.Skip("trailing-dot hosts now match; update this test and delete the note")
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
