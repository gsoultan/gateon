package middleware

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/config"
)

// RealIPGlobal returns a middleware that resolves the real client IP and updates r.RemoteAddr
// using the trust settings from the global configuration.
func RealIPGlobal() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trustCloudflare := config.EffectiveTrustCloudflare()

			// Apply the core RealIP logic with the resolved trust setting
			RealIP(trustCloudflare)(next).ServeHTTP(w, r)
		})
	}
}
