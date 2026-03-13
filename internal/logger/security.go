package logger

import (
	"net/http"
	"strings"
)

// SecurityEvent logs a security-relevant event for audit and monitoring.
func SecurityEvent(event string, r *http.Request, reason string) {
	L.Warn().
		Str("event", event).
		Str("ip", clientIP(r)).
		Str("path", r.URL.Path).
		Str("reason", reason).
		Msg("security event")
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i >= 0 {
		ip = ip[:i]
	}
	return ip
}
