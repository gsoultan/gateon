package domain

import (
	"errors"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

// MiddlewareServiceImpl implements MiddlewareService.
type MiddlewareServiceImpl struct {
	store                 config.MiddlewareStore
	routeStore            config.RouteStore
	invalidateRouteProxies func(func(*gateonv1.Route) bool)
}

// NewMiddlewareService creates a MiddlewareService.
func NewMiddlewareService(store config.MiddlewareStore, routeStore config.RouteStore, invalidateRouteProxies func(func(*gateonv1.Route) bool)) MiddlewareService {
	return &MiddlewareServiceImpl{store: store, routeStore: routeStore, invalidateRouteProxies: invalidateRouteProxies}
}

// ListPaginated returns paginated middlewares.
func (s *MiddlewareServiceImpl) ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Middleware, int32) {
	return s.store.ListPaginated(page, pageSize, search)
}

// SaveMiddleware validates, assigns ID if needed, persists, and invalidates affected route proxies.
func (s *MiddlewareServiceImpl) SaveMiddleware(mw *gateonv1.Middleware) error {
	if mw.Id == "" {
		mw.Id = uuid.NewString()
	}
	if err := s.store.Update(mw); err != nil {
		return err
	}
	s.invalidateRouteProxies(func(rt *gateonv1.Route) bool {
		for _, mid := range rt.Middlewares {
			if mid == mw.Id {
				return true
			}
		}
		return false
	})
	return nil
}

// DeleteMiddleware removes the middleware and invalidates affected route proxies.
func (s *MiddlewareServiceImpl) DeleteMiddleware(id string) error {
	if id == "" {
		return errors.New("missing middleware id")
	}
	if err := s.store.Delete(id); err != nil {
		return err
	}
	s.invalidateRouteProxies(func(rt *gateonv1.Route) bool {
		for _, mid := range rt.Middlewares {
			if mid == id {
				return true
			}
		}
		return false
	})
	return nil
}
