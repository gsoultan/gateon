package config

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// MiddlewareStore defines the contract for working with middleware configurations.
// It is implemented by MiddlewareRegistry.
type MiddlewareStore interface {
	List(ctx context.Context) []*gateonv1.Middleware
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Middleware, int32)
	All(ctx context.Context) map[string]*gateonv1.Middleware
	Get(ctx context.Context, id string) (*gateonv1.Middleware, bool)
	Update(ctx context.Context, m *gateonv1.Middleware) error
	Delete(ctx context.Context, id string) error
}
