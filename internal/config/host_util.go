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
