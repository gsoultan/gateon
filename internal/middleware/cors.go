package middleware

import (
	"context"
	"net/http"

	"github.com/rs/cors"
)

// CORSConfig defines the configuration for the CORS middleware.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int
	Debug            bool
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing (CORS).
func CORS(cfg CORSConfig) Middleware {
	c := cors.New(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   cfg.AllowedMethods,
		AllowedHeaders:   cfg.AllowedHeaders,
		ExposedHeaders:   cfg.ExposedHeaders,
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           cfg.MaxAge,
		Debug:            cfg.Debug,
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(CORSHandledContextKey) != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Mark as handled for downstream middlewares
			wrappedNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(context.WithValue(r.Context(), CORSHandledContextKey, true))
				next.ServeHTTP(w, r)
			})

			c.Handler(wrappedNext).ServeHTTP(w, r)
		})
	}
}

// BypassCORS returns a middleware that automatically handles CORS preflight requests
// by allowing all origins, methods, and headers. It is intended to be used as a
// fallback when no specific CORS middleware is configured, restoring v1.5.0 behavior.
func BypassCORS() Middleware {
	c := cors.New(cors.Options{
		AllowOriginFunc:  func(origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400,
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(CORSHandledContextKey) != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Mark as handled for downstream middlewares
			wrappedNext := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r = r.WithContext(context.WithValue(r.Context(), CORSHandledContextKey, true))
				next.ServeHTTP(w, r)
			})

			c.Handler(wrappedNext).ServeHTTP(w, r)
		})
	}
}
