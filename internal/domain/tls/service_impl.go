package tls

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serviceImpl implements Service.
type serviceImpl struct {
	store       config.TLSOptionStore
	routeStore  config.RouteStore
	invalidator proxy.Invalidator
	logger      logger.Logger
}

// NewService creates a TLS Option Service.
func NewService(store config.TLSOptionStore, routeStore config.RouteStore, invalidator proxy.Invalidator, l logger.Logger) Service {
	return &serviceImpl{store: store, routeStore: routeStore, invalidator: invalidator, logger: l}
}

// ListPaginated returns paginated TLS options.
func (s *serviceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

// GetTLSOption returns a single TLS option by ID.
func (s *serviceImpl) GetTLSOption(ctx context.Context, id string) (*gateonv1.TLSOption, bool) {
	return s.store.Get(ctx, id)
}

// SaveTLSOption validates, assigns ID if needed, persists, and invalidates global TLS cache.
func (s *serviceImpl) SaveTLSOption(ctx context.Context, opt *gateonv1.TLSOption) error {
	if opt.Id == "" {
		opt.Id = uuid.NewString()
	}
	if err := s.store.Update(ctx, opt); err != nil {
		return err
	}
	s.invalidator.InvalidateTLS()
	return nil
}

// DeleteTLSOption removes the TLS option and invalidates global TLS cache.
func (s *serviceImpl) DeleteTLSOption(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing TLS option id")
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.invalidator.InvalidateTLS()
	return nil
}
