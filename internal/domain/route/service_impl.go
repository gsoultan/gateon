package route

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serviceImpl implements Service.
type serviceImpl struct {
	store       config.RouteStore
	invalidator proxy.Invalidator
	logger      logger.Logger
}

// NewService creates a Route Service.
func NewService(store config.RouteStore, invalidator proxy.Invalidator, l logger.Logger) Service {
	return &serviceImpl{store: store, invalidator: invalidator, logger: l}
}

// ListPaginated returns paginated routes.
func (s *serviceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string, filter *config.RouteFilter) ([]*gateonv1.Route, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search, filter)
}

// GetRoute returns a single route by ID.
func (s *serviceImpl) GetRoute(ctx context.Context, id string) (*gateonv1.Route, bool) {
	return s.store.Get(ctx, id)
}

// SaveRoute validates, assigns ID if needed, persists, and invalidates proxy.
func (s *serviceImpl) SaveRoute(ctx context.Context, rt *gateonv1.Route) error {
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
func (s *serviceImpl) DeleteRoute(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing route id")
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidator.InvalidateRoute(id)
	return nil
}
