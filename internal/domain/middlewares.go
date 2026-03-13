package domain

import (
	"context"
	"errors"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

// MiddlewareServiceImpl implements MiddlewareService.
type MiddlewareServiceImpl struct {
	store      config.MiddlewareStore
	routeStore config.RouteStore
	invalidator ProxyInvalidator
}

// NewMiddlewareService creates a MiddlewareService.
func NewMiddlewareService(store config.MiddlewareStore, routeStore config.RouteStore, invalidator ProxyInvalidator) MiddlewareService {
	return &MiddlewareServiceImpl{store: store, routeStore: routeStore, invalidator: invalidator}
}

// ListPaginated returns paginated middlewares.
func (s *MiddlewareServiceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Middleware, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

// SaveMiddleware validates, assigns ID if needed, persists, and invalidates affected route proxies.
func (s *MiddlewareServiceImpl) SaveMiddleware(ctx context.Context, mw *gateonv1.Middleware) error {
	if mw.Id == "" {
		mw.Id = uuid.NewString()
	}
	if err := s.store.Update(ctx, mw); err != nil {
		return err
	}
	s.invalidator.InvalidateRoutes(func(rt *gateonv1.Route) bool {
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
func (s *MiddlewareServiceImpl) DeleteMiddleware(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing middleware id")
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidator.InvalidateRoutes(func(rt *gateonv1.Route) bool {
		for _, mid := range rt.Middlewares {
			if mid == id {
				return true
			}
		}
		return false
	})
	return nil
}
