package domain

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// MiddlewareServiceImpl implements MiddlewareService.
type MiddlewareServiceImpl struct {
	store               config.MiddlewareStore
	routeStore          config.RouteStore
	invalidator         ProxyInvalidator
	validator           MiddlewareConfigValidator
	wafCacheInvalidator WAFCacheInvalidator
}

// NewMiddlewareService creates a MiddlewareService.
func NewMiddlewareService(store config.MiddlewareStore, routeStore config.RouteStore, invalidator ProxyInvalidator, validator MiddlewareConfigValidator) MiddlewareService {
	return NewMiddlewareServiceWithOptions(store, routeStore, invalidator, validator, nil)
}

// NewMiddlewareServiceWithOptions creates a MiddlewareService with optional WAF cache invalidation.
func NewMiddlewareServiceWithOptions(store config.MiddlewareStore, routeStore config.RouteStore, invalidator ProxyInvalidator, validator MiddlewareConfigValidator, wafCacheInvalidator WAFCacheInvalidator) MiddlewareService {
	return &MiddlewareServiceImpl{
		store:               store,
		routeStore:          routeStore,
		invalidator:         invalidator,
		validator:           validator,
		wafCacheInvalidator: wafCacheInvalidator,
	}
}

// ListPaginated returns paginated middlewares.
func (s *MiddlewareServiceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Middleware, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

// SaveMiddleware validates, assigns ID if needed, persists, and invalidates affected route proxies.
func (s *MiddlewareServiceImpl) SaveMiddleware(ctx context.Context, mw *gateonv1.Middleware) error {
	if s.validator != nil {
		if err := s.validator.Validate(mw); err != nil {
			return err
		}
	}
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
	if s.wafCacheInvalidator != nil && mw.Type == "waf" {
		s.wafCacheInvalidator.Invalidate()
	}
	return nil
}

// DeleteMiddleware removes the middleware, removes its references from routes, and invalidates affected route proxies.
func (s *MiddlewareServiceImpl) DeleteMiddleware(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing middleware id")
	}
	mw, _ := s.store.Get(ctx, id)

	// 1. Find all routes using this middleware and remove it from them
	routes := s.routeStore.List(ctx)
	var affectedRouteIDs []string
	for _, rt := range routes {
		found := false
		newMws := make([]string, 0, len(rt.Middlewares))
		for _, mid := range rt.Middlewares {
			if mid == id {
				found = true
				continue
			}
			newMws = append(newMws, mid)
		}
		if found {
			affectedRouteIDs = append(affectedRouteIDs, rt.Id)
			rt.Middlewares = newMws
			if err := s.routeStore.Update(ctx, rt); err != nil {
				// We log and continue, as failing here might leave things in inconsistent state
			}
		}
	}

	// 2. Delete the middleware itself
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}

	// 3. Invalidate affected routes
	for _, rid := range affectedRouteIDs {
		s.invalidator.InvalidateRoute(rid)
	}

	if s.wafCacheInvalidator != nil && mw != nil && mw.Type == "waf" {
		s.wafCacheInvalidator.Invalidate()
	}
	return nil
}

// RoutesUsingMiddleware returns routes that reference the given middleware ID.
func (s *MiddlewareServiceImpl) RoutesUsingMiddleware(ctx context.Context, middlewareID string) []*gateonv1.Route {
	if middlewareID == "" {
		return nil
	}
	var out []*gateonv1.Route
	for _, rt := range s.routeStore.List(ctx) {
		for _, mid := range rt.Middlewares {
			if mid == middlewareID {
				out = append(out, rt)
				break
			}
		}
	}
	return out
}
