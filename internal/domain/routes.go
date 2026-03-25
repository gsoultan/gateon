package domain

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// RouteServiceImpl implements RouteService.
type RouteServiceImpl struct {
	store       config.RouteStore
	invalidator ProxyInvalidator
}

// NewRouteService creates a RouteService.
func NewRouteService(store config.RouteStore, invalidator ProxyInvalidator) RouteService {
	return &RouteServiceImpl{store: store, invalidator: invalidator}
}

// ListPaginated returns paginated routes.
func (s *RouteServiceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *config.RouteFilter) ([]*gateonv1.Route, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search, filter)
}

// SaveRoute validates, assigns ID if needed, persists, and invalidates proxy.
func (s *RouteServiceImpl) SaveRoute(ctx context.Context, rt *gateonv1.Route) error {
	if rt.ServiceId == "" {
		return errors.New("missing service_id")
	}
	rtLower := strings.ToLower(rt.Type)
	if rtLower != "tcp" && rtLower != "udp" && rt.Rule == "" {
		return errors.New("missing rule (required for http/grpc routes)")
	}
	if rt.Id == "" {
		rt.Id = uuid.NewString()
	}
	if err := s.store.Update(ctx, rt); err != nil {
		return err
	}
	s.invalidator.InvalidateRoute(rt.Id)
	return nil
}

// DeleteRoute removes the route and invalidates its proxy.
func (s *RouteServiceImpl) DeleteRoute(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing route id")
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidator.InvalidateRoute(id)
	return nil
}
