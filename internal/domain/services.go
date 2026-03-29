package domain

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ServiceServiceImpl implements ServiceService.
type ServiceServiceImpl struct {
	store       config.ServiceStore
	routeStore  config.RouteStore
	invalidator ProxyInvalidator
}

// NewServiceService creates a ServiceService.
func NewServiceService(store config.ServiceStore, routeStore config.RouteStore, invalidator ProxyInvalidator) ServiceService {
	return &ServiceServiceImpl{store: store, routeStore: routeStore, invalidator: invalidator}
}

// ListPaginated returns paginated services.
func (s *ServiceServiceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.Service, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

func (s *ServiceServiceImpl) GetService(ctx context.Context, id string) (*gateonv1.Service, bool) {
	return s.store.Get(ctx, id)
}

// SaveService validates, assigns ID if needed, persists, and invalidates affected route proxies.
func (s *ServiceServiceImpl) SaveService(ctx context.Context, svc *gateonv1.Service) error {
	if svc.Id == "" {
		svc.Id = uuid.NewString()
	}
	if err := s.store.Update(ctx, svc); err != nil {
		return err
	}
	s.invalidator.InvalidateRoutes(func(rt *gateonv1.Route) bool { return rt.ServiceId == svc.Id })
	return nil
}

// DeleteService removes the service, removes its references from routes, and invalidates affected route proxies.
func (s *ServiceServiceImpl) DeleteService(ctx context.Context, id string) error {
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
			_ = s.routeStore.Update(ctx, rt)
		}
	}

	// 2. Delete the service itself
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}

	// 3. Invalidate proxies
	for _, rid := range affectedIDs {
		s.invalidator.InvalidateRoute(rid)
	}

	return nil
}
