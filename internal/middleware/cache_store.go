package middleware

import (
	"context"
	"net/http"
	"time"
)

// CacheBackend abstracts storage for response cache (memory or Redis).
// Consumer-centric interface for get/set cached responses.
type CacheBackend interface {
	Get(ctx context.Context, key string) (status int, headers http.Header, body []byte, ok bool)
	Set(ctx context.Context, key string, status int, headers http.Header, body []byte, ttl time.Duration)
}
