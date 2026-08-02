// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"net/http"

	"github.com/gsoultan/gateon/internal/config"
)

// RealIPGlobal returns a middleware that resolves the real client IP and updates r.RemoteAddr
// using the trust settings from the global configuration.
func RealIPGlobal() Middleware {
	hTrust := RealIP(true)
	hNoTrust := RealIP(false)

	return func(next http.Handler) http.Handler {
		nextTrust := hTrust(next)
		nextNoTrust := hNoTrust(next)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.EffectiveTrustCloudflare() {
				nextTrust.ServeHTTP(w, r)
			} else {
				nextNoTrust.ServeHTTP(w, r)
			}
		})
	}
}
