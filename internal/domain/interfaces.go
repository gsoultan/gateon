package domain

import (
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// RouteService encapsulates route business logic: validation, ID generation, persistence, proxy invalidation.
type RouteService interface {
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Route, int32)
	SaveRoute(rt *gateonv1.Route) error
	DeleteRoute(id string) error
}

// ServiceService encapsulates service business logic: validation, ID generation, persistence, proxy invalidation.
type ServiceService interface {
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	SaveService(svc *gateonv1.Service) error
	DeleteService(id string) error
}

// EntryPointService encapsulates entrypoint business logic: validation, ID generation, type inference, persistence.
type EntryPointService interface {
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32)
	SaveEntryPoint(ep *gateonv1.EntryPoint) error
	DeleteEntryPoint(id string) error
}

// MiddlewareService encapsulates middleware business logic: validation, ID generation, persistence, proxy invalidation.
type MiddlewareService interface {
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Middleware, int32)
	SaveMiddleware(mw *gateonv1.Middleware) error
	DeleteMiddleware(id string) error
}

// TLSOptionService encapsulates TLS option business logic: validation, ID generation, persistence.
type TLSOptionService interface {
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32)
	SaveTLSOption(opt *gateonv1.TLSOption) error
	DeleteTLSOption(id string) error
}
