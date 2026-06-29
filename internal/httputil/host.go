package httputil

import (
	"net"
	"strings"
)

// StripPort removes the port part from a host string (e.g. "localhost:8080" -> "localhost").
// It handles IPv6 addresses correctly, returning the bare address without brackets
// (e.g. "[::1]:8080" -> "::1" and "[::1]" -> "::1") so the result can be parsed by net.ParseIP.
func StripPort(host string) string {
	if host == "" {
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
