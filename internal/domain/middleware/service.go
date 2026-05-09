package middleware

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ConfigValidator validates middleware configuration before persistence.
type ConfigValidator interface {
	Validate(mw *gateonv1.Middleware) error
}

// WAFCacheInvalidator invalidates the WAF instance cache when a WAF middleware is saved or deleted.
// Prevents stale WAF instances when config changes. Optional; pass nil to disable.
type WAFCacheInvalidator interface {
	Invalidate()
}

// Service encapsulates middleware business logic: validation, ID generation, persistence, proxy invalidation.
type Service interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Middleware, int32)
	GetMiddleware(ctx context.Context, id string) (*gateonv1.Middleware, bool)
	SaveMiddleware(ctx context.Context, mw *gateonv1.Middleware) error
	DeleteMiddleware(ctx context.Context, id string) error
	RoutesUsingMiddleware(ctx context.Context, middlewareID string) []*gateonv1.Route
}
