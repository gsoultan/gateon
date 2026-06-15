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
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	// No port present. Strip surrounding brackets from a bare IPv6 literal (e.g. "[::1]").
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}
