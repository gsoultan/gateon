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
	cloudflareIPs  []netip.Prefix
)

func init() {
	// Built-in Cloudflare IP ranges (accurate as of 2024-05)
	cfv4 := []string{
		"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
		"104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
		"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
		"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
	}
	cfv6 := []string{
		"2400:cb00::/32", "2405:8100::/32", "2405:b500::/32", "2606:4700::/32",
		"2803:f800::/32", "2c0f:f248::/32", "2a06:98c0::/29",
	}
	for _, cidr := range append(cfv4, cfv6...) {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			cloudflareIPs = append(cloudflareIPs, prefix)
		}
	}

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

func isCloudflareIP(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, n := range cloudflareIPs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsTrusted reports whether the given remote address is a trusted proxy.
// If trustCloudflare is true, it also trusts built-in Cloudflare IP ranges.
func IsTrusted(remoteAddr string, trustCloudflare bool) bool {
	host := httputil.StripPort(remoteAddr)
	if isTrustedAddr(host) {
		return true
	}
	if trustCloudflare {
		return isCloudflareIP(host)
	}
	return false
}

func isTrustedProxy(remoteAddr string) bool {
	return IsTrusted(remoteAddr, false)
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
	remoteIP := httputil.StripPort(r.RemoteAddr)
	isTrusted := IsTrusted(r.RemoteAddr, trustCloudflare)

	if !isTrusted {
		return remoteIP
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
