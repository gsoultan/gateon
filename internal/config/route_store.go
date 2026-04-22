package config

import (
	"context"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RouteStore defines the contract for working with route configurations.
// It is implemented by RouteRegistry.
type RouteStore interface {
	List(ctx context.Context) []*gateonv1.Route
	ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *RouteFilter) ([]*gateonv1.Route, int32)
	All(ctx context.Context) map[string]*gateonv1.Route
	Get(ctx context.Context, id string) (*gateonv1.Route, bool)
	Update(ctx context.Context, rt *gateonv1.Route) error
	Delete(ctx context.Context, id string) error
}
