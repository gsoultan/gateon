package domain

import (
	"context"
	"errors"

	"github.com/gateon/gateon/internal/config"
	gateonv1 "github.com/gateon/gateon/proto/gateon/v1"
	"github.com/google/uuid"
)

// TLSOptionServiceImpl implements TLSOptionService.
type TLSOptionServiceImpl struct {
	store config.TLSOptionStore
}

// NewTLSOptionService creates a TLSOptionService.
func NewTLSOptionService(store config.TLSOptionStore) TLSOptionService {
	return &TLSOptionServiceImpl{store: store}
}

// ListPaginated returns paginated TLS options.
func (s *TLSOptionServiceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.TLSOption, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

// SaveTLSOption validates, assigns ID if needed, and persists.
func (s *TLSOptionServiceImpl) SaveTLSOption(ctx context.Context, opt *gateonv1.TLSOption) error {
	if opt.Id == "" {
		opt.Id = uuid.NewString()
	}
	return s.store.Update(ctx, opt)
}

// DeleteTLSOption removes the TLS option.
func (s *TLSOptionServiceImpl) DeleteTLSOption(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing tls option id")
	}
	return s.store.Delete(ctx, id)
}
