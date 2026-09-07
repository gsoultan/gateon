// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"strings"
)

// RouteHostIsExact returns true if routeHost is an exact host (e.g. api.example.com),
// false if it is a wildcard (e.g. *.example.com). Used by SNI to prefer exact matches.
func RouteHostIsExact(routeHost string) bool {
	return routeHost != "" && !strings.HasPrefix(strings.ToLower(routeHost), "*.")
}

// HostMatches checks if the request host matches the route's host specification,
// supporting wildcards like *.example.com.
// stripRootLabel removes the trailing dot from a fully-qualified host name.
//
// "app.example.com." and "app.example.com" are the same name -- the trailing dot
// is the DNS root label, and clients, proxies and health checkers do send the
// fully-qualified spelling. String comparison does not know that, so without
// this a request for the FQDN matched neither the host's own routes nor a
// wildcard, and fell through to whatever host-agnostic route existed. That is
// the same failure as a path with dot segments: one resource, two spellings, and
// the middleware chain attached to only one of them.
//
// The bare root "." is left alone; it is not a host anyone routes to.
func stripRootLabel(h string) string {
	if len(h) > 1 && h[len(h)-1] == '.' {
		return h[:len(h)-1]
	}
	return h
}

// NormalizeHost puts a host into the single spelling used as a routing key:
// lower-cased, with the DNS root label removed.
//
// Both sides have to agree. Route keys are built from the rule and lookups come
// from the request, so normalising only one of them just moves which spelling
// fails to match.
func NormalizeHost(h string) string {
	return strings.ToLower(stripRootLabel(h))
}

func HostMatches(rh string, qh string) bool {
	if rh == "" {
		return true
	}

	// Strip the port, then the brackets around an IPv6 literal.
	//
	// These were one if/else, which meant a bracketed literal lost its brackets
	// only when it arrived without a port: "[::1]" matched a route host of "::1"
	// and "[::1]:8080" did not, because stripping the port left "[::1]" and the
	// else branch had already been skipped. A request carrying a port is the
	// ordinary case, so the route matched the spelling nobody sends.
	//
	// The order matters: the port separator is the last colon *outside* the
	// brackets, so "]" at the end means what looks like a port separator is part
	// of the address.
	if idx := strings.LastIndexByte(qh, ':'); idx != -1 && !strings.HasSuffix(qh, "]") {
		qh = qh[:idx]
	}
	if len(qh) > 1 && qh[0] == '[' && qh[len(qh)-1] == ']' {
		qh = qh[1 : len(qh)-1]
	}

	// One resource, one spelling: see stripRootLabel.
	qh = stripRootLabel(qh)
	rh = stripRootLabel(rh)

	// Case-insensitive comparison without allocation
	if !strings.HasPrefix(rh, "*.") {
		return strings.EqualFold(qh, rh)
	}

	// Handle wildcards like *.example.com
	// rh is "*.example.com", suffix is ".example.com"
	if len(qh) < len(rh)-1 {
		return false
	}
	suffix := rh[1:]
	// Compare suffix part case-insensitively without allocating lowercased strings
	qhSuffix := qh[len(qh)-len(suffix):]
	return strings.EqualFold(qhSuffix, suffix)
}
