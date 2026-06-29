package request

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
// It is optimized to use a stack-allocated buffer.
func GenerateID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])

	// req- + 16 hex chars = 20 chars
	var buf [20]byte
	copy(buf[:4], "req-")
	hex.Encode(buf[4:], b[:])
	return string(buf[:])
}
