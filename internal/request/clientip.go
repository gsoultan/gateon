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
	// EnvTrustedProxies is a comma-separated list of CIDRs that are trusted to provide X-Forwarded-For or CF-Connecting-IP.
	EnvTrustedProxies = "GATEON_TRUSTED_PROXIES"
)

var (
	trustedProxies []*net.IPNet
)

func init() {
	if s := os.Getenv(EnvTrustedProxies); s != "" {
		for _, cidr := range strings.Split(s, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, network, err := net.ParseCIDR(cidr)
			if err == nil {
				trustedProxies = append(trustedProxies, network)
			} else {
				// Try parsing as single IP
				if ip := net.ParseIP(cidr); ip != nil {
					mask := net.CIDRMask(32, 32)
					if ip.To4() == nil {
						mask = net.CIDRMask(128, 128)
					}
					trustedProxies = append(trustedProxies, &net.IPNet{IP: ip, Mask: mask})
				}
			}
		}
	}
}

func isTrustedProxy(remoteAddr string) bool {
	if len(trustedProxies) == 0 {
		return true // Default to trust all if not configured (User Friendly)
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIP returns the client IP from the request, using CF-Connecting-IP when
// trustCloudflare is true (e.g. when Gateon is behind Cloudflare), otherwise
// X-Forwarded-For (leftmost), falling back to RemoteAddr.
func GetClientIP(r *http.Request, trustCloudflare bool) string {
	if !isTrustedProxy(r.RemoteAddr) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host == "" {
			return r.RemoteAddr
		}
		return host
	}

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
