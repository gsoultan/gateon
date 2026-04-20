package request

import (
	"context"
	"net/http"
)

const countryKey contextKey = "client_country"

// GetCountry returns the client country from the request context or "XX".
func GetCountry(r *http.Request) string {
	if country, ok := r.Context().Value(countryKey).(string); ok {
		return country
	}
	return "XX"
}

// WithCountry adds a client country to the context.
func WithCountry(ctx context.Context, country string) context.Context {
	return context.WithValue(ctx, countryKey, country)
}
