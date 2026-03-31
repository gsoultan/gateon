package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/gsoultan/gateon/internal/logger"
)

type ContextKey string

const (
	EntryPointIDContextKey ContextKey = "entrypoint_id"
	IsManagementContextKey ContextKey = "is_management"
)

// Middleware defines a function that wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Recovery returns a middleware that recovers from panics, logs the stack, and returns 500.
// Prevents a single panicking handler from crashing the server.
func Recovery() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.L.Error().
						Interface("panic", err).
						Str("path", r.URL.Path).
						Str("method", r.Method).
						Str("stack", string(debug.Stack())).
						Msg("handler panic recovered")
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Chain composes multiple middlewares into a single middleware.
// The middlewares are executed in the order they are provided.
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}
