package domain

import (
	"errors"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

// ServiceServiceImpl implements ServiceService.
type ServiceServiceImpl struct {
	store                 config.ServiceStore
	routeStore            config.RouteStore
	invalidateRouteProxies func(func(*gateonv1.Route) bool)
}

// NewServiceService creates a ServiceService.
func NewServiceService(store config.ServiceStore, routeStore config.RouteStore, invalidateRouteProxies func(func(*gateonv1.Route) bool)) ServiceService {
	return &ServiceServiceImpl{store: store, routeStore: routeStore, invalidateRouteProxies: invalidateRouteProxies}
}

// ListPaginated returns paginated services.
func (s *ServiceServiceImpl) ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Service, int32) {
	return s.store.ListPaginated(page, pageSize, search)
}

// SaveService validates, assigns ID if needed, persists, and invalidates affected route proxies.
func (s *ServiceServiceImpl) SaveService(svc *gateonv1.Service) error {
	if svc.Id == "" {
		svc.Id = uuid.NewString()
	}
	if err := s.store.Update(svc); err != nil {
		return err
	}
	s.invalidateRouteProxies(func(rt *gateonv1.Route) bool { return rt.ServiceId == svc.Id })
	return nil
}

// DeleteService removes the service and invalidates affected route proxies.
func (s *ServiceServiceImpl) DeleteService(id string) error {
	if id == "" {
		return errors.New("missing service id")
	}
	if err := s.store.Delete(id); err != nil {
		return err
	}
	s.invalidateRouteProxies(func(rt *gateonv1.Route) bool { return rt.ServiceId == id })
	return nil
}
