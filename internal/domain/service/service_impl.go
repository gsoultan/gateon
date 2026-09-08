// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// serviceImpl implements Service.
type serviceImpl struct {
	store       config.ServiceStore
	routeStore  config.RouteStore
	invalidator proxy.Invalidator
	logger      logger.Logger
}

// NewService creates a Service Service.
func NewService(store config.ServiceStore, routeStore config.RouteStore, invalidator proxy.Invalidator, l logger.Logger) Service {
	return &serviceImpl{store: store, routeStore: routeStore, invalidator: invalidator, logger: l}
}

// ListPaginated returns paginated services.
func (s *serviceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

// GetService returns a service by ID.
func (s *serviceImpl) GetService(ctx context.Context, id string) (*gateonv1.Service, bool) {
	return s.store.Get(ctx, id)
}

// SaveService validates, assigns ID if needed, persists, and invalidates affected route proxies.
func (s *serviceImpl) SaveService(ctx context.Context, svc *gateonv1.Service) error {
	if svc.Id == "" {
		svc.Id = uuid.NewString()
	}
	if err := s.store.Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to update service: %w", err)
	}
	s.invalidator.InvalidateRoutes(func(rt *gateonv1.Route) bool { return rt.ServiceId == svc.Id })
	return nil
}

// DeleteService removes the service, removes its references from routes, and invalidates affected route proxies.
func (s *serviceImpl) DeleteService(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing service id")
	}

	// 1. Find and update routes using this service
	affectedIDs := ClearRouteReferences(ctx, s.routeStore, id)

	// 2. Delete the service itself
	if err := s.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	// 3. Invalidate proxies
	for _, rid := range affectedIDs {
		s.invalidator.InvalidateRoute(rid)
	}

	return nil
}

// ClearRouteReferences removes a service id from every route naming it and
// returns the ids of the routes that changed.
//
// Exported because deleting a service is reachable from two transports and was
// implemented twice: the REST handler goes through this package, while
// internal/api talked to the stores directly and cleared nothing, so the same
// operation left two different persisted states depending on how the caller
// arrived. One copy of the rule is the fix; a second correct copy would only
// have delayed the next divergence.
//
// A route whose Update fails is skipped rather than aborting the rest: the
// service is going away regardless, and stopping halfway would leave some routes
// updated and some not, which is worse than leaving one behind for the operator
// to see.
//
// Each route is cloned before being changed. RouteRegistry.List returns the
// registry's own slice of live pointers, and the request path reads those same
// objects while it routes -- writing ServiceId in place was a data race the
// detector reports against every concurrent read of the field. Cloning also
// means a route whose Update fails is left exactly as it was, rather than
// detached in memory while the stored copy still names the service.
func ClearRouteReferences(ctx context.Context, routes config.RouteStore, serviceID string) []string {
	var affected []string
	for _, rt := range routes.List(ctx) {
		if rt.ServiceId != serviceID {
			continue
		}
		affected = append(affected, rt.Id)

		clone, ok := proto.Clone(rt).(*gateonv1.Route)
		if !ok {
			continue
		}
		clone.ServiceId = ""
		if err := routes.Update(ctx, clone); err != nil {
			continue
		}
	}
	return affected
}
