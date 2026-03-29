package domain

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TLSOptionServiceImpl implements TLSOptionService.
type TLSOptionServiceImpl struct {
	store       config.TLSOptionStore
	routeStore  config.RouteStore
	invalidator ProxyInvalidator
}

// NewTLSOptionService creates a TLSOptionService.
func NewTLSOptionService(store config.TLSOptionStore, routeStore config.RouteStore, invalidator ProxyInvalidator) TLSOptionService {
	return &TLSOptionServiceImpl{store: store, routeStore: routeStore, invalidator: invalidator}
}

// ListPaginated returns paginated TLS options.
func (s *TLSOptionServiceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

func (s *TLSOptionServiceImpl) GetTLSOption(ctx context.Context, id string) (*gateonv1.TLSOption, bool) {
	return s.store.Get(ctx, id)
}

// SaveTLSOption validates, assigns ID if needed, and persists.
func (s *TLSOptionServiceImpl) SaveTLSOption(ctx context.Context, opt *gateonv1.TLSOption) error {
	if opt.Id == "" {
		opt.Id = uuid.NewString()
	}
	if err := s.store.Update(ctx, opt); err != nil {
		return err
	}
	// Invalidate routes using this TLS option
	s.invalidator.InvalidateRoutes(func(rt *gateonv1.Route) bool {
		return rt.Tls != nil && rt.Tls.OptionId == opt.Id
	})
	return nil
}

// DeleteTLSOption removes the TLS option, removes its references from routes, and invalidates affected route proxies.
func (s *TLSOptionServiceImpl) DeleteTLSOption(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing tls option id")
	}

	// 1. Find and update routes using this TLS option
	routes := s.routeStore.List(ctx)
	var affectedIDs []string
	for _, rt := range routes {
		if rt.Tls != nil && rt.Tls.OptionId == id {
			affectedIDs = append(affectedIDs, rt.Id)
			rt.Tls.OptionId = "" // Remove reference
			_ = s.routeStore.Update(ctx, rt)
		}
	}

	// 2. Delete the option
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}

	// 3. Invalidate proxies
	for _, rid := range affectedIDs {
		s.invalidator.InvalidateRoute(rid)
	}

	return nil
}
