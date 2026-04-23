package httputil

import "strings"

// StripPort removes the port part from a host string (e.g. "localhost:8080" -> "localhost").
// It handles IPv6 addresses correctly (e.g. "[::1]:8080" -> "[::1]").
func StripPort(host string) string {
	if idx := strings.LastIndexByte(host, ':'); idx != -1 {
		// If it's IPv6 [::1]:8080, it has a ']' before the last ':'
		if idx > 0 && host[idx-1] == ']' {
			return host[:idx]
		}
		// If it's a simple host:port like localhost:8080
		// Check if there are other colons before the last one (IPv6 without brackets)
		if !strings.ContainsRune(host[:idx], ':') {
			return host[:idx]
		}
	}
	return host
}
