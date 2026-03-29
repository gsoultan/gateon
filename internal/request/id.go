package request

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
)

type contextKey string

const idKey contextKey = "request_id"

// GetID returns the request ID from the request context or "unknown".
func GetID(r *http.Request) string {
	if id, ok := r.Context().Value(idKey).(string); ok {
		return id
	}
	return "unknown"
}

// WithID adds a request ID to the context.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, idKey, id)
}

// GenerateID creates a new unique request ID.
func GenerateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("req-%x", b)
}
