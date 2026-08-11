// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"sort"
	"strings"
	"sync/atomic"
)

// routeOriginProvider supplies the hostnames the routing table says this gateway
// answers on.
//
// It is a package-level hook for the same reason the WAF rule store is: the
// middleware factory is built per route, on a path that runs whenever the
// configuration changes, and threading a route store through every construction
// site to read one list would be a lot of plumbing for a value that is the same
// for all of them. The server sets it once at startup.
var routeOriginProvider atomic.Pointer[func() []string]

// SetRouteOriginProvider records where route-derived origins come from.
//
// Passing nil clears it, which is what tests want and what a gateway with no
// routing table gets: no derived origins, and the off-origin rules stay quiet
// rather than comparing against a guess.
func SetRouteOriginProvider(fn func() []string) {
	if fn == nil {
		routeOriginProvider.Store(nil)
		return
	}
	routeOriginProvider.Store(&fn)
}

// routeOrigins returns the hostnames the routing table declares.
func routeOrigins() []string {
	if fn := routeOriginProvider.Load(); fn != nil {
		return (*fn)()
	}
	return nil
}

// resolveOrigins combines what the operator declared with what the routing table
// implies, and returns a sorted, de-duplicated list.
//
// Both sources are configuration, which is the whole point: gwaf v0.4.1 stopped
// reading the Host header because an attacker writes it as freely as the
// destination being judged, so "Host: evil.tld" with "redirect_to=evil.tld"
// compared same-origin and passed. A route's Host() rule and an operator's list
// are things the deployment decided; a request header is not.
//
// Sorted so the config fingerprint is stable across map iteration order, and
// de-duplicated because a gateway routinely has several routes on one host.
func resolveOrigins(declared []string) []string {
	seen := make(map[string]struct{}, len(declared)+8)
	add := func(h string) {
		h = strings.TrimSpace(strings.ToLower(h))
		// A port is not part of an origin for this comparison, and gwaf ignores
		// one anyway; stripping it here keeps the fingerprint from treating
		// "example.com" and "example.com:8443" as different policies.
		if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i+1:], ".") {
			h = h[:i]
		}
		if h == "" {
			return
		}
		seen[h] = struct{}{}
	}

	for _, h := range declared {
		add(h)
	}
	for _, h := range routeOrigins() {
		add(h)
	}

	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
