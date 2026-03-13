package domain

import (
	"context"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// RouteService encapsulates route business logic: validation, ID generation, persistence, proxy invalidation.
type RouteService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Route, int32)
	SaveRoute(ctx context.Context, rt *gateonv1.Route) error
	DeleteRoute(ctx context.Context, id string) error
}

// ServiceService encapsulates service business logic: validation, ID generation, persistence, proxy invalidation.
type ServiceService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	SaveService(ctx context.Context, svc *gateonv1.Service) error
	DeleteService(ctx context.Context, id string) error
}

// EntryPointService encapsulates entrypoint business logic: validation, ID generation, type inference, persistence.
type EntryPointService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32)
	SaveEntryPoint(ctx context.Context, ep *gateonv1.EntryPoint) error
	DeleteEntryPoint(ctx context.Context, id string) error
}

// MiddlewareService encapsulates middleware business logic: validation, ID generation, persistence, proxy invalidation.
type MiddlewareService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Middleware, int32)
	SaveMiddleware(ctx context.Context, mw *gateonv1.Middleware) error
	DeleteMiddleware(ctx context.Context, id string) error
}

// TLSOptionService encapsulates TLS option business logic: validation, ID generation, persistence.
type TLSOptionService interface {
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32)
	SaveTLSOption(ctx context.Context, opt *gateonv1.TLSOption) error
	DeleteTLSOption(ctx context.Context, id string) error
}
