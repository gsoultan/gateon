package middleware

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/request"
)

// ForwardedHeadersConfig configures, per route, how the X-Forwarded-Proto value
// forwarded to the backend is determined. It is the operator-facing control
// point for the scheme that request.Scheme resolves (and therefore what the
// HTTP, WebSocket, forward-auth, and security-header layers observe).
type ForwardedHeadersConfig struct {
	// Proto, when set to "http" or "https", forces the scheme regardless of the
	// transport or any inbound header. Empty leaves the value to be derived.
	Proto string
	// TrustForwardHeader, when true, honors the inbound X-Forwarded-Proto on this
	// route even if the immediate peer is not in GATEON_TRUSTED_PROXIES. Use only
	// when a trusted upstream terminates TLS but is not covered by the global
	// trusted-proxy list. Ignored when Proto is set.
	TrustForwardHeader bool
}

// ForwardedHeaders returns a middleware that records an explicit, validated
// X-Forwarded-Proto override in the request context. request.Scheme honors that
// override ahead of TLS state and trusted-proxy detection, so the downstream
// proxy writes the operator-chosen scheme. When the configuration yields no
// concrete value the middleware is a no-op and the default resolution applies.
func ForwardedHeaders(cfg ForwardedHeadersConfig) Middleware {
	override := request.NormalizeProto(cfg.Proto)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if proto := resolveProto(r, override, cfg.TrustForwardHeader); proto != "" {
				r = r.WithContext(request.WithForwardedProto(r.Context(), proto))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resolveProto picks the scheme to pin: an explicit override wins; otherwise, if
// the route opts to trust the inbound header, the validated inbound value is
// used. Returns "" to defer to the default request.Scheme resolution.
func resolveProto(r *http.Request, override string, trustForward bool) string {
	if override != "" {
		return override
	}
	if trustForward {
		return request.NormalizeProto(r.Header.Get(request.HeaderXForwardedProto))
	}
	return ""
}
