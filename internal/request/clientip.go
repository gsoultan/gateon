package request

import (
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	// HeaderCloudflareConnectingIP is set by Cloudflare to the connecting client IP.
	HeaderCloudflareConnectingIP = "CF-Connecting-IP"
	// HeaderXForwardedFor is the standard proxy header for client IP chain.
	HeaderXForwardedFor = "X-Forwarded-For"
	// EnvTrustCloudflareHeaders controls global default for trusting CF-Connecting-IP.
	EnvTrustCloudflareHeaders = "GATEON_TRUST_CLOUDFLARE_HEADERS"
)

// GetClientIP returns the client IP from the request, using CF-Connecting-IP when
// trustCloudflare is true (e.g. when Gateon is behind Cloudflare), otherwise
// X-Forwarded-For (leftmost), falling back to RemoteAddr.
func GetClientIP(r *http.Request, trustCloudflare bool) string {
	if trustCloudflare {
		if cf := r.Header.Get(HeaderCloudflareConnectingIP); cf != "" {
			ip := strings.TrimSpace(cf)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	if xff := r.Header.Get(HeaderXForwardedFor); xff != "" {
		// Leftmost is original client; rightmost is closest proxy
		left := strings.TrimSpace(strings.Split(xff, ",")[0])
		if left != "" {
			// Strip port if present
			host, _, err := net.SplitHostPort(left)
			if err == nil {
				return host
			}
			return left
		}
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}

// TrustCloudflareFromEnv returns true if GATEON_TRUST_CLOUDFLARE_HEADERS is set
// to a truthy value (true, 1, yes). Used as default when middleware config omits
// trust_cloudflare_headers.
func TrustCloudflareFromEnv() bool {
	s := strings.TrimSpace(strings.ToLower(os.Getenv(EnvTrustCloudflareHeaders)))
	if s == "" {
		return false
	}
	return s == "true" || s == "1" || s == "yes"
}

// ParseTrustCloudflare parses a config value for trust_cloudflare_headers.
// If empty, falls back to TrustCloudflareFromEnv().
func ParseTrustCloudflare(val string) bool {
	s := strings.TrimSpace(strings.ToLower(val))
	if s == "" {
		return TrustCloudflareFromEnv()
	}
	return s == "true" || s == "1" || s == "yes"
}

// ParseTrustCloudflareStrict parses trust_cloudflare_headers without env fallback.
// Returns false when empty or invalid.
func ParseTrustCloudflareStrict(val string) bool {
	s := strings.TrimSpace(strings.ToLower(val))
	return s == "true" || s == "1" || s == "yes"
}
