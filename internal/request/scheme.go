package request

import (
	"context"
	"net/http"
	"strings"
)

// HeaderXForwardedProto is the de-facto standard header a TLS-terminating proxy
// sets to convey the scheme the client originally used.
const HeaderXForwardedProto = "X-Forwarded-Proto"

// protoOverrideKey is the context key under which the forwardedheaders
// middleware records an explicit, operator-chosen X-Forwarded-Proto value.
type protoOverrideKey struct{}

// WithForwardedProto returns a context carrying an explicit X-Forwarded-Proto
// override. Scheme honors it ahead of TLS state and trusted-proxy detection,
// giving operators per-route control via the forwardedheaders middleware. proto
// is expected to already be a validated "http" or "https"; other values are
// ignored by Scheme.
func WithForwardedProto(ctx context.Context, proto string) context.Context {
	return context.WithValue(ctx, protoOverrideKey{}, proto)
}

// protoOverride returns the operator-set scheme override from ctx, or "".
func protoOverride(ctx context.Context) string {
	if v, ok := ctx.Value(protoOverrideKey{}).(string); ok {
		return v
	}
	return ""
}

// Scheme returns the scheme ("http" or "https") under which the request reached
// the edge. Resolution order:
//  1. an explicit per-route override set by the forwardedheaders middleware;
//  2. a direct TLS connection;
//  3. X-Forwarded-Proto, but only when the immediate peer (r.RemoteAddr) is a
//     trusted proxy per GATEON_TRUSTED_PROXIES, which prevents an untrusted
//     client from spoofing the scheme.
//
// The forwarded value is validated against the {http, https} allow-list;
// anything else falls back to "http".
func Scheme(r *http.Request) string {
	if rs := GetRequestState(r); rs != nil && rs.ForwardedProto != "" {
		return rs.ForwardedProto
	}
	if p := NormalizeProto(protoOverride(r.Context())); p != "" {
		return p
	}
	if r.TLS != nil {
		return "https"
	}
	if isTrustedProxy(r.RemoteAddr) {
		if p := NormalizeProto(r.Header.Get(HeaderXForwardedProto)); p != "" {
			return p
		}
	}
	return "http"
}

// IsSecure reports whether the request reached the edge over a secure (TLS)
// connection, either directly or via a trusted TLS-terminating proxy.
func IsSecure(r *http.Request) bool {
	return Scheme(r) == "https"
}

// NormalizeProto extracts and validates the leftmost token of an
// X-Forwarded-Proto value. Chained proxies may emit a list (e.g. "https, http");
// the leftmost token reflects the original client. Returns "http" or "https",
// or "" when the value is neither.
func NormalizeProto(v string) string {
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, ','); i != -1 {
		v = v[:i]
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "https":
		return "https"
	case "http":
		return "http"
	default:
		return ""
	}
}
