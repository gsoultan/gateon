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
	routes := s.routeStore.List(ctx)
	var affectedIDs []string
	for _, rt := range routes {
		if rt.ServiceId == id {
			affectedIDs = append(affectedIDs, rt.Id)
			rt.ServiceId = "" // Remove reference
			if err := s.routeStore.Update(ctx, rt); err != nil {
				// Continue to next route even if one fails
				continue
			}
		}
	}

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
