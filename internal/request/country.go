package request

import (
	"context"
	"net/http"
	"strings"
)

const countryKey contextKey = "client_country"

// GetCountry returns the client country from the request context,
// or from CF-IPCountry header if present (and trusted), or "XX" (Unknown).
func GetCountry(r *http.Request) string {
	if country, ok := r.Context().Value(countryKey).(string); ok {
		return country
	}
	if TrustCloudflareFromEnv() {
		if cfCountry := r.Header.Get("CF-IPCountry"); cfCountry != "" {
			return strings.ToUpper(cfCountry)
		}
	}
	return "XX"
}

// WithCountry adds a client country to the context.
func WithCountry(ctx context.Context, country string) context.Context {
	return context.WithValue(ctx, countryKey, country)
}
