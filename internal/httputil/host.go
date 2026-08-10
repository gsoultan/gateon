// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package httputil

import (
	"net"
	"net/netip"
	"strings"
)

// IsLoopback returns true if the given IP address is a local loopback address.
func IsLoopback(ipStr string) bool {
	host := StripPort(ipStr)
	if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// StripPort removes the port part from a host string (e.g. "localhost:8080" -> "localhost").
// It handles IPv6 addresses correctly, returning the bare address without brackets
// (e.g. "[::1]:8080" -> "::1" and "[::1]" -> "::1") so the result can be parsed by net.ParseIP.
func StripPort(host string) string {
	if host == "" {
		return host
	}
	// No colon means there is no port and no bracketed IPv6 — nothing to strip.
	// This case has to be answered here rather than falling through to the
	// net.SplitHostPort fallback below, because that call fails for a bare
	// address and its failure path allocates an *AddrError that is then
	// discarded. Bare addresses are the common input on the request path:
	// X-Forwarded-For and X-Real-IP carry an address with no port, and this
	// runs for every request.
	if strings.IndexByte(host, ':') == -1 {
		return host
	}
	// Fast path: "host:port" or "[ipv6]:port" -> bare host without brackets.
	if last := strings.LastIndexByte(host, ':'); last != -1 {
		// If it has brackets, it's an IPv6 address.
		if strings.HasPrefix(host, "[") {
			if end := strings.IndexByte(host, ']'); end != -1 {
				// host is [ipv6]:port or just [ipv6]
				if last > end {
					// [ipv6]:port
					return host[1:end]
				}
				// [ipv6]
				return host[1:end]
			}
		}
		// host:port where host is not bracketed (IPv4 or hostname)
		// But wait, it could be a bare IPv6 without brackets (invalid for SplitHostPort but possible input)
		// Usually RemoteAddr is host:port.
		if strings.Count(host, ":") == 1 {
			return host[:last]
		}
	}

	// Fallback for complex cases (e.g. multiple colons without brackets)
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

// SingleJoiningSlash joins two URL paths with exactly one slash between them.
func SingleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
