package domain

import (
	"errors"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

// RouteServiceImpl implements RouteService.
type RouteServiceImpl struct {
	store               config.RouteStore
	invalidateRouteProxy func(string)
}

// NewRouteService creates a RouteService.
func NewRouteService(store config.RouteStore, invalidateRouteProxy func(string)) RouteService {
	return &RouteServiceImpl{store: store, invalidateRouteProxy: invalidateRouteProxy}
}

// ListPaginated returns paginated routes.
func (s *RouteServiceImpl) ListPaginated(page, pageSize int32, search string) ([]*gateonv1.Route, int32) {
	return s.store.ListPaginated(page, pageSize, search)
}

// SaveRoute validates, assigns ID if needed, persists, and invalidates proxy.
func (s *RouteServiceImpl) SaveRoute(rt *gateonv1.Route) error {
	if rt.Rule == "" || rt.ServiceId == "" {
		return errors.New("missing rule/service_id")
	}
	if rt.Id == "" {
		rt.Id = uuid.NewString()
	}
	if err := s.store.Update(rt); err != nil {
		return err
	}
	s.invalidateRouteProxy(rt.Id)
	return nil
}

// DeleteRoute removes the route and invalidates its proxy.
func (s *RouteServiceImpl) DeleteRoute(id string) error {
	if id == "" {
		return errors.New("missing route id")
	}
	if err := s.store.Delete(id); err != nil {
		return err
	}
	s.invalidateRouteProxy(id)
	return nil
}
