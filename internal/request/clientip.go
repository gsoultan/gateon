// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/security/art"
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
	trustedProxies = art.NewTree()
	cloudflareIPs  = art.NewTree()
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
		_ = cloudflareIPs.InsertCIDR(cidr)
	}

	if s := os.Getenv(EnvTrustedProxies); s != "" {
		for _, cidr := range strings.Split(s, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if strings.Contains(cidr, "/") {
				_ = trustedProxies.InsertCIDR(cidr)
			} else {
				// Single IP
				if addr, err := netip.ParseAddr(cidr); err == nil {
					bits := 32
					if addr.Is6() {
						bits = 128
					}
					_ = trustedProxies.InsertCIDR(fmt.Sprintf("%s/%d", addr.String(), bits))
				}
			}
		}
	}
}

// isTrustedIP reports whether the given IP is within the configured trusted-proxy set.
func isTrustedIP(ip netip.Addr) bool {
	return trustedProxies.ContainsAddr(ip)
}

func isCloudflareIP(ip netip.Addr) bool {
	return cloudflareIPs.ContainsAddr(ip)
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
	if rs := GetRequestState(r); rs != nil {
		if rs.ClientRemoteAddr != "" {
			return rs.ClientRemoteAddr
		}
	}

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

	if ip, ok := clientFromForwardedFor(r.Header[HeaderXForwardedFor]); ok {
		return ip
	}
	return host
}

// clientFromForwardedFor walks an X-Forwarded-For chain right to left and
// returns the first address that is not a trusted proxy, or the leftmost one
// when every hop is trusted.
//
// The chain is every X-Forwarded-For header line, in order, not only the
// first: repeated fields are one comma-separated list (RFC 9110 section 5.3).
// A trusted proxy that adds its own line rather than extending the one it
// received -- HAProxy's "option forwardfor" does, and says so -- leaves the
// client's line first and its own last, so reading only the first line
// returned exactly the address the client chose. The walk starts at the last
// line for the same reason it starts at the right of one.
func clientFromForwardedFor(lines []string) (string, bool) {
	// Zero-allocation right-to-left parsing of X-Forwarded-For
	for i := len(lines) - 1; i >= 0; i-- {
		if ip, ok := clientFromForwardedLine(lines[i], i == 0); ok {
			return ip, true
		}
	}
	return "", false
}

// clientFromForwardedLine walks one X-Forwarded-For line right to left.
// firstLine says it is the first line of the chain, whose leftmost address is
// the client when every hop is trusted.
func clientFromForwardedLine(xff string, firstLine bool) (string, bool) {
	for {
		lastComma := strings.LastIndexByte(xff, ',')
		part := xff
		if lastComma != -1 {
			part = xff[lastComma+1:]
			xff = xff[:lastComma]
		}
		if ip, ok := forwardedClient(part, firstLine && lastComma == -1); ok {
			return ip, true
		}
		if lastComma == -1 {
			return "", false // keep walking left, onto the previous line
		}
	}
}

// forwardedClient returns the hop's address when it is the client: the first
// untrusted address, or the leftmost of a chain whose every hop was trusted.
// A port is stripped (it sometimes appears); an empty or unparseable token is
// skipped.
func forwardedClient(part string, chainStart bool) (string, bool) {
	token := strings.TrimSpace(part)
	if token == "" {
		return "", false
	}
	cleanIP := httputil.StripPort(token)
	parsed, err := netip.ParseAddr(cleanIP)
	if err != nil {
		return "", false
	}
	if !isTrustedIP(parsed) || chainStart {
		return cleanIP, true
	}
	return "", false
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
