package config

import (
	"context"

	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// RouteStore defines the contract for working with route configurations.
// It is implemented by RouteRegistry.
// RouteFilter filters routes by type, host, path, and status.
type RouteFilter struct {
	Type   string // http, grpc, graphql, tcp, udp
	Host   string
	Path   string
	Status string // active, paused
}

type RouteStore interface {
	List(ctx context.Context) []*gateonv1.Route
	ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *RouteFilter) ([]*gateonv1.Route, int32)
	All(ctx context.Context) map[string]*gateonv1.Route
	Get(ctx context.Context, id string) (*gateonv1.Route, bool)
	Update(ctx context.Context, rt *gateonv1.Route) error
	Delete(ctx context.Context, id string) error
}

// ServiceStore defines the contract for working with service configurations.
// It is implemented by ServiceRegistry.
type ServiceStore interface {
	List(ctx context.Context) []*gateonv1.Service
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	Get(ctx context.Context, id string) (*gateonv1.Service, bool)
	Update(ctx context.Context, s *gateonv1.Service) error
	Delete(ctx context.Context, id string) error
}

// EntryPointStore defines the contract for working with entrypoint configurations.
// It is implemented by EntryPointRegistry.
type EntryPointStore interface {
	List(ctx context.Context) []*gateonv1.EntryPoint
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32)
	Get(ctx context.Context, id string) (*gateonv1.EntryPoint, bool)
	Update(ctx context.Context, ep *gateonv1.EntryPoint) error
	Delete(ctx context.Context, id string) error
}

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

// TLSOptionStore defines the contract for working with TLS option configurations.
// It is implemented by TLSOptionRegistry.
type TLSOptionStore interface {
	List(ctx context.Context) []*gateonv1.TLSOption
	ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32)
	All(ctx context.Context) map[string]*gateonv1.TLSOption
	Get(ctx context.Context, id string) (*gateonv1.TLSOption, bool)
	Update(ctx context.Context, opt *gateonv1.TLSOption) error
	Delete(ctx context.Context, id string) error
}

// GlobalConfigStore defines the contract for working with global configuration.
// It is implemented by GlobalRegistry.
type GlobalConfigStore interface {
	Get(ctx context.Context) *gateonv1.GlobalConfig
	Update(ctx context.Context, conf *gateonv1.GlobalConfig) error
	ConfigFileExists() bool
}

