package middleware

import (
	"net/http"
	"time"
)

// RetryConfig defines the configuration for the retry middleware.
type RetryConfig struct {
	Attempts        int
	InitialInterval time.Duration
}

// Retry returns a middleware that retries failed requests.
// Full retry (body buffering, response inspection, backoff) is not implemented:
// the request is forwarded once. A full implementation would require wrapping
// the request body and ResponseWriter to decide whether to retry on status/errors.
func Retry(cfg RetryConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts := cfg.Attempts
			if attempts <= 0 {
				attempts = 1
			}
			for i := 0; i < attempts; i++ {
				next.ServeHTTP(w, r)
				break // Single attempt until body buffering and response inspection are implemented
			}
		})
	}
}
