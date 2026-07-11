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

	// Strip port from qh if present (e.g. "localhost:8080" -> "localhost")
	if idx := strings.LastIndexByte(qh, ':'); idx != -1 && !strings.HasSuffix(qh, "]") {
		qh = qh[:idx]
	} else if strings.HasPrefix(qh, "[") && strings.HasSuffix(qh, "]") {
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
