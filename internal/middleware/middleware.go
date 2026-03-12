package middleware

import "net/http"

type ContextKey string

const (
	EntryPointIDContextKey ContextKey = "entrypoint_id"
)

// Middleware defines a function that wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

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
