package config

import (
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
)

// RouteStore defines the contract for working with route configurations.
// It is implemented by RouteRegistry.
type RouteStore interface {
	List() []*gateonv1.Route
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Route, int32)
	All() map[string]*gateonv1.Route
	Get(id string) (*gateonv1.Route, bool)
	Update(rt *gateonv1.Route) error
	Delete(id string) error
}

// ServiceStore defines the contract for working with service configurations.
// It is implemented by ServiceRegistry.
type ServiceStore interface {
	List() []*gateonv1.Service
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Service, int32)
	Get(id string) (*gateonv1.Service, bool)
	Update(s *gateonv1.Service) error
	Delete(id string) error
}

// EntryPointStore defines the contract for working with entrypoint configurations.
// It is implemented by EntryPointRegistry.
type EntryPointStore interface {
	List() []*gateonv1.EntryPoint
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32)
	Get(id string) (*gateonv1.EntryPoint, bool)
	Update(ep *gateonv1.EntryPoint) error
	Delete(id string) error
}

// MiddlewareStore defines the contract for working with middleware configurations.
// It is implemented by MiddlewareRegistry.
type MiddlewareStore interface {
	List() []*gateonv1.Middleware
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Middleware, int32)
	All() map[string]*gateonv1.Middleware
	Get(id string) (*gateonv1.Middleware, bool)
	Update(m *gateonv1.Middleware) error
	Delete(id string) error
}

// TLSOptionStore defines the contract for working with TLS option configurations.
// It is implemented by TLSOptionRegistry.
type TLSOptionStore interface {
	List() []*gateonv1.TLSOption
	ListPaginated(page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32)
	All() map[string]*gateonv1.TLSOption
	Get(id string) (*gateonv1.TLSOption, bool)
	Update(opt *gateonv1.TLSOption) error
	Delete(id string) error
}

// GlobalConfigStore defines the contract for working with global configuration.
// It is implemented by GlobalRegistry.
type GlobalConfigStore interface {
	Get() *gateonv1.GlobalConfig
	Update(conf *gateonv1.GlobalConfig) error
}

