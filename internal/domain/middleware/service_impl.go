// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serviceImpl implements Service.
type serviceImpl struct {
	store               config.MiddlewareStore
	routeStore          config.RouteStore
	invalidator         proxy.Invalidator
	validator           ConfigValidator
	wafCacheInvalidator WAFCacheInvalidator
	logger              logger.Logger
}

// NewService creates a Middleware Service.
func NewService(store config.MiddlewareStore, routeStore config.RouteStore, invalidator proxy.Invalidator, validator ConfigValidator, wafCacheInvalidator WAFCacheInvalidator, l logger.Logger) Service {
	return &serviceImpl{
		store:               store,
		routeStore:          routeStore,
		invalidator:         invalidator,
		validator:           validator,
		wafCacheInvalidator: wafCacheInvalidator,
		logger:              l,
	}
}

// ListPaginated returns paginated middlewares.
func (s *serviceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Middleware, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

// GetMiddleware returns a single middleware by ID.
func (s *serviceImpl) GetMiddleware(ctx context.Context, id string) (*gateonv1.Middleware, bool) {
	return s.store.Get(ctx, id)
}

// SaveMiddleware validates, assigns ID if needed, persists, and invalidates affected route proxies.
func (s *serviceImpl) SaveMiddleware(ctx context.Context, mw *gateonv1.Middleware) error {
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
func (s *serviceImpl) DeleteMiddleware(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing middleware id")
	}
	mw, mwFound := s.store.Get(ctx, id)

	// 1. Find all routes using this middleware and remove it from them
	routes := s.routeStore.List(ctx)
	var affectedRouteIDs []string
	var stillReferencing []string
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
		if !found {
			continue
		}
		rt.Middlewares = newMws
		if err := s.routeStore.Update(ctx, rt); err != nil {
			// Recorded, not swallowed. See the guard below.
			stillReferencing = append(stillReferencing, rt.Id)
			s.logger.LogError("failed to unlink middleware from route",
				"error", err, "middleware_id", id, "route_id", rt.Id)
			continue
		}
		affectedRouteIDs = append(affectedRouteIDs, rt.Id)
	}

	// 2. Refuse to delete while a route still points at it.
	//
	// The router resolves a route's middleware IDs with a plain store lookup and
	// skips any that miss -- no log, no error. So deleting the middleware here
	// while a route still references it makes that route quietly lose it, and if
	// it was the WAF or an auth middleware the route is then unprotected. This
	// used to `continue` past the failure and delete anyway, returning nil, so
	// the API reported success for an operation that had silently opened a hole.
	//
	// Leaving the middleware in place is the safe end of the trade: the routes
	// that did update no longer use it, and an orphaned middleware record costs
	// nothing but a row.
	if len(stillReferencing) > 0 {
		for _, rid := range affectedRouteIDs {
			s.invalidator.InvalidateRoute(rid)
		}
		return fmt.Errorf("middleware %s not deleted: %d route(s) still reference it (%s)",
			id, len(stillReferencing), strings.Join(stillReferencing, ", "))
	}

	// 3. Delete the middleware itself
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}

	// 4. Invalidate affected routes
	for _, rid := range affectedRouteIDs {
		s.invalidator.InvalidateRoute(rid)
	}

	// The WAF cache is dropped whenever the type is unknown as well as when it
	// is "waf". Get's miss used to be discarded into a nil middleware, which
	// skipped this and left the deleted policy live in cache. An unnecessary
	// rebuild costs a few milliseconds; a missed one keeps enforcing a rule the
	// operator has deleted.
	if s.wafCacheInvalidator != nil && (!mwFound || mw == nil || mw.Type == "waf") {
		s.wafCacheInvalidator.Invalidate()
	}
	return nil
}

// RoutesUsingMiddleware returns routes that reference the given middleware ID.
func (s *serviceImpl) RoutesUsingMiddleware(ctx context.Context, middlewareID string) []*gateonv1.Route {
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
