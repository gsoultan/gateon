// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"context"
	"net/http"
	"strings"
)

const countryKey contextKey = "client_country"

// CountryResolver is an interface for resolving IPs to country codes.
type CountryResolver interface {
	Resolve(ip string) string
}

var (
	globalResolver CountryResolver
)

// RegisterCountryResolver registers a global resolver for IP to Country mapping.
func RegisterCountryResolver(r CountryResolver) {
	globalResolver = r
}

// GetCountry returns the client country from the request context,
// or from CF-IPCountry header if present (and trusted), or "XX" (Unknown).
// isCountryCode reports whether s is a two-letter ISO-3166 alpha-2 code.
func isCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := range 2 {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

func GetCountry(r *http.Request, trustCloudflare bool) string {
	if rs := GetRequestState(r); rs != nil {
		if rs.ClientCountry != "" {
			return rs.ClientCountry
		}
	}
	if country, ok := r.Context().Value(countryKey).(string); ok {
		return country
	}
	if trustCloudflare {
		// Validated, unlike before. This value becomes a Prometheus label, and
		// an unvalidated one is a permanent series per distinct string with a
		// 1 MiB header to fill it from. A country code is two ASCII letters or
		// Cloudflare's "XX" for unknown; anything else is not a country and is
		// treated as absent so the resolver below answers instead.
		if cfCountry := r.Header.Get("CF-IPCountry"); isCountryCode(cfCountry) {
			return strings.ToUpper(cfCountry)
		}
	}
	if globalResolver != nil {
		ip := GetClientIP(r, trustCloudflare)
		return globalResolver.Resolve(ip)
	}
	return "XX"
}

// WithCountry adds a client country to the context.
func WithCountry(ctx context.Context, country string) context.Context {
	return context.WithValue(ctx, countryKey, country)
}
