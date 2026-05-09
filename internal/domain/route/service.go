package route

import (
	"context"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Service encapsulates route business logic: validation, ID generation, persistence, proxy invalidation.
type Service interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *config.RouteFilter) ([]*gateonv1.Route, int32)
	GetRoute(ctx context.Context, id string) (*gateonv1.Route, bool)
	SaveRoute(ctx context.Context, rt *gateonv1.Route) error
	DeleteRoute(ctx context.Context, id string) error
}
