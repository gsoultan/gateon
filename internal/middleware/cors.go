package middleware

import (
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
		return c.Handler(next)
	}
}
