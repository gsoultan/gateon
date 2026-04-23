package request

import (
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/httputil"
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
	trustedProxies []netip.Prefix
)

func init() {
	if s := os.Getenv(EnvTrustedProxies); s != "" {
		for _, cidr := range strings.Split(s, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if prefix, err := netip.ParsePrefix(cidr); err == nil {
				trustedProxies = append(trustedProxies, prefix)
			} else if addr, err := netip.ParseAddr(cidr); err == nil {
				// Single IP as /32 or /128
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				trustedProxies = append(trustedProxies, netip.PrefixFrom(addr, bits))
			}
		}
	}
}

func isTrustedProxy(remoteAddr string) bool {
	if len(trustedProxies) == 0 {
		return true // Default to trust all if not configured (User Friendly)
	}
	host := httputil.StripPort(remoteAddr)
	ip, err := netip.ParseAddr(host)
	if err != nil {
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
		return httputil.StripPort(r.RemoteAddr)
	}

	if trustCloudflare {
		if cf := r.Header.Get(HeaderCloudflareConnectingIP); cf != "" {
			ipStr := strings.TrimSpace(cf)
			if _, err := netip.ParseAddr(ipStr); err == nil {
				return ipStr
			}
		}
	}
	if xff := r.Header.Get(HeaderXForwardedFor); xff != "" {
		// Leftmost is original client; rightmost is closest proxy
		left := xff
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			left = xff[:idx]
		}
		left = strings.TrimSpace(left)
		if left != "" {
			return httputil.StripPort(left)
		}
	}
	return httputil.StripPort(r.RemoteAddr)
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
