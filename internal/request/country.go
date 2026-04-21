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
func GetCountry(r *http.Request) string {
	if country, ok := r.Context().Value(countryKey).(string); ok {
		return country
	}
	if TrustCloudflareFromEnv() {
		if cfCountry := r.Header.Get("CF-IPCountry"); cfCountry != "" {
			return strings.ToUpper(cfCountry)
		}
	}
	if globalResolver != nil {
		ip := GetClientIP(r, TrustCloudflareFromEnv())
		return globalResolver.Resolve(ip)
	}
	return "XX"
}

// WithCountry adds a client country to the context.
func WithCountry(ctx context.Context, country string) context.Context {
	return context.WithValue(ctx, countryKey, country)
}
