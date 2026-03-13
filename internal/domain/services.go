package domain

import (
	"context"
	"errors"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

// ServiceServiceImpl implements ServiceService.
type ServiceServiceImpl struct {
	store      config.ServiceStore
	routeStore config.RouteStore
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

// DeleteService removes the service and invalidates affected route proxies.
func (s *ServiceServiceImpl) DeleteService(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing service id")
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidator.InvalidateRoutes(func(rt *gateonv1.Route) bool { return rt.ServiceId == id })
	return nil
}
