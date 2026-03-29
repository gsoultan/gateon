package domain

import (
	"context"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RouteService encapsulates route business logic: validation, ID generation, persistence, proxy invalidation.
type RouteService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *config.RouteFilter) ([]*gateonv1.Route, int32)
	GetRoute(ctx context.Context, id string) (*gateonv1.Route, bool)
	SaveRoute(ctx context.Context, rt *gateonv1.Route) error
	DeleteRoute(ctx context.Context, id string) error
}

// ServiceService encapsulates service business logic: validation, ID generation, persistence, proxy invalidation.
type ServiceService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	GetService(ctx context.Context, id string) (*gateonv1.Service, bool)
	SaveService(ctx context.Context, svc *gateonv1.Service) error
	DeleteService(ctx context.Context, id string) error
}

// EntryPointService encapsulates entrypoint business logic: validation, ID generation, type inference, persistence.
type EntryPointService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32)
	GetEntryPoint(ctx context.Context, id string) (*gateonv1.EntryPoint, bool)
	SaveEntryPoint(ctx context.Context, ep *gateonv1.EntryPoint) error
	DeleteEntryPoint(ctx context.Context, id string) error
}

// MiddlewareConfigValidator validates middleware configuration before persistence.
type MiddlewareConfigValidator interface {
	Validate(mw *gateonv1.Middleware) error
}

// WAFCacheInvalidator invalidates the WAF instance cache when a WAF middleware is saved or deleted.
// Prevents stale WAF instances when config changes. Optional; pass nil to disable.
type WAFCacheInvalidator interface {
	Invalidate()
}

// MiddlewareService encapsulates middleware business logic: validation, ID generation, persistence, proxy invalidation.
type MiddlewareService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Middleware, int32)
	GetMiddleware(ctx context.Context, id string) (*gateonv1.Middleware, bool)
	SaveMiddleware(ctx context.Context, mw *gateonv1.Middleware) error
	DeleteMiddleware(ctx context.Context, id string) error
	RoutesUsingMiddleware(ctx context.Context, middlewareID string) []*gateonv1.Route
}

// TLSOptionService encapsulates TLS option business logic: validation, ID generation, persistence.
type TLSOptionService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32)
	GetTLSOption(ctx context.Context, id string) (*gateonv1.TLSOption, bool)
	SaveTLSOption(ctx context.Context, opt *gateonv1.TLSOption) error
	DeleteTLSOption(ctx context.Context, id string) error
}

// CanaryService handles automated traffic shifting.
type CanaryService interface {
	StartCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) (string, error)
}
