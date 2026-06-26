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

// isTrustedAddr reports whether the given host/IP string is within the
// configured trusted-proxy set.
func isTrustedAddr(host string) bool {
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

// isTrustedProxy reports whether the immediate peer (RemoteAddr) is a trusted
// proxy allowed to set forwarding headers.
//
// SECURITY: when GATEON_TRUSTED_PROXIES is unset we DENY by default — forwarding
// headers (X-Forwarded-For / CF-Connecting-IP / X-Forwarded-Proto) are
// attacker-controlled and must not be believed unless the operator has
// explicitly declared which upstream proxies are trusted. Deployments that
// genuinely sit behind a proxy must set GATEON_TRUSTED_PROXIES to the proxy
// CIDR(s); to intentionally trust every peer (legacy behavior) set it to
// "0.0.0.0/0,::/0".
func isTrustedProxy(remoteAddr string) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	return isTrustedAddr(httputil.StripPort(remoteAddr))
}

// GetClientIP returns the real client IP from the request.
//
// When the immediate peer is a trusted proxy it consults forwarding headers:
// CF-Connecting-IP (only when trustCloudflare is true) takes precedence,
// otherwise X-Forwarded-For is parsed RIGHT-TO-LEFT, skipping addresses that are
// themselves trusted proxies, and the first untrusted address is returned. The
// leftmost XFF token is never trusted directly because it is the position a
// client fully controls. Falls back to RemoteAddr.
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
		parts := strings.Split(xff, ",")
		// Walk from the closest proxy (rightmost) toward the client (leftmost),
		// popping trusted hops. The first non-trusted address is the real client.
		for i := len(parts) - 1; i >= 0; i-- {
			ip := httputil.StripPort(strings.TrimSpace(parts[i]))
			if ip == "" {
				continue
			}
			if isTrustedAddr(ip) {
				continue // a known proxy hop — keep walking left
			}
			if _, err := netip.ParseAddr(ip); err == nil {
				return ip
			}
		}
		// Every hop was a trusted proxy: the leftmost entry is the origin client.
		left := httputil.StripPort(strings.TrimSpace(parts[0]))
		if _, err := netip.ParseAddr(left); err == nil {
			return left
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
