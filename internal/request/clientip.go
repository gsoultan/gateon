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

// isTrustedIP reports whether the given IP is within the configured trusted-proxy set.
func isTrustedIP(ip netip.Addr) bool {
	for i := range trustedProxies {
		if trustedProxies[i].Contains(ip) {
			return true
		}
	}
	return false
}

func isCloudflareIP(ip netip.Addr) bool {
	for i := range cloudflareIPs {
		if cloudflareIPs[i].Contains(ip) {
			return true
		}
	}
	return false
}

// IsTrusted reports whether the given remote address is a trusted proxy.
// If trustCloudflare is true, it also trusts built-in Cloudflare IP ranges.
func IsTrusted(remoteAddr string, trustCloudflare bool) bool {
	host := httputil.StripPort(remoteAddr)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if isTrustedIP(ip) {
		return true
	}
	if trustCloudflare {
		return isCloudflareIP(ip)
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
	remoteAddr := r.RemoteAddr
	host := httputil.StripPort(remoteAddr)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}

	isTrusted := isTrustedIP(ip)
	if !isTrusted && trustCloudflare {
		isTrusted = isCloudflareIP(ip)
	}

	if !isTrusted {
		return host
	}

	if trustCloudflare {
		if cf := r.Header.Get(HeaderCloudflareConnectingIP); cf != "" {
			cf = strings.TrimSpace(cf)
			if _, err := netip.ParseAddr(cf); err == nil {
				return cf
			}
		}
	}

	if xff := r.Header.Get(HeaderXForwardedFor); xff != "" {
		// Zero-allocation right-to-left parsing of X-Forwarded-For
		for {
			lastComma := strings.LastIndexByte(xff, ',')
			part := xff
			if lastComma != -1 {
				part = xff[lastComma+1:]
				xff = xff[:lastComma]
			}

			token := strings.TrimSpace(part)
			if token == "" {
				if lastComma == -1 {
					break
				}
				continue
			}

			// Strip port if present in XFF (sometimes happens)
			cleanIP := httputil.StripPort(token)
			parsed, err := netip.ParseAddr(cleanIP)
			if err != nil {
				if lastComma == -1 {
					break
				}
				continue
			}

			if isTrustedIP(parsed) {
				if lastComma == -1 {
					// Every hop was trusted, return the leftmost
					return cleanIP
				}
				continue // Keep walking left
			}

			return cleanIP // Found the first untrusted IP
		}
	}
	return host
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
