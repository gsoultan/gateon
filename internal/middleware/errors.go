package middleware

import (
	"net/http"
)

// ErrorsConfig defines the configuration for the errors middleware.
type ErrorsConfig struct {
	// StatusCodes is the list of status codes that should trigger the custom error page.
	StatusCodes []int
	// Service is the URL of the service that provides the custom error pages.
	// For simplicity in this implementation, we'll just use a map of status code to custom body.
	CustomPages map[int]string
}

// Errors returns a middleware that handles custom error pages.
// Best-effort only: if the downstream handler already wrote a body, the custom page
// may be appended rather than replaced. For full Traefik-style behavior, use a
// dedicated error service or buffer the response before writing.
func Errors(cfg ErrorsConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &StatusResponseWriter{ResponseWriter: w, Status: http.StatusOK}
			next.ServeHTTP(sw, r)

			for _, code := range cfg.StatusCodes {
				if sw.Status == code {
					if page, ok := cfg.CustomPages[code]; ok {
						w.Header().Set("Content-Type", "text/html; charset=utf-8")
						_, _ = w.Write([]byte(page))
					}
					break
				}
			}
		})
	}
}
