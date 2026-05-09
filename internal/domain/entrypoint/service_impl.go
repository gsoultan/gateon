package entrypoint

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serviceImpl implements Service.
type serviceImpl struct {
	store  config.EntryPointStore
	logger logger.Logger
}

// NewService creates an EntryPoint Service.
func NewService(store config.EntryPointStore, l logger.Logger) Service {
	return &serviceImpl{store: store, logger: l}
}

// ListPaginated returns paginated entrypoints.
func (s *serviceImpl) ListPaginated(ctx context.Context, page, pageSize int32, search string) ([]*gateonv1.EntryPoint, int32) {
	return s.store.ListPaginated(ctx, page, pageSize, search)
}

// GetEntryPoint returns a single entrypoint by ID.
func (s *serviceImpl) GetEntryPoint(ctx context.Context, id string) (*gateonv1.EntryPoint, bool) {
	return s.store.Get(ctx, id)
}

// SaveEntryPoint validates, assigns ID if needed, infers type, and persists.
func (s *serviceImpl) SaveEntryPoint(ctx context.Context, ep *gateonv1.EntryPoint) error {
	if ep.Address == "" {
		return errors.New("missing address")
	}
	if ep.Id == "" {
		ep.Id = uuid.NewString()
	}
	inferEntryPointType(ep)
	return s.store.Update(ctx, ep)
}

// DeleteEntryPoint removes the entrypoint.
func (s *serviceImpl) DeleteEntryPoint(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("missing entrypoint id")
	}
	return s.store.Delete(ctx, id)
}

func inferEntryPointType(ep *gateonv1.EntryPoint) {
	hasTCP, hasUDP := false, false
	for _, p := range ep.Protocols {
		if p == gateonv1.EntryPoint_TCP_PROTO {
			hasTCP = true
		}
		if p == gateonv1.EntryPoint_UDP_PROTO {
			hasUDP = true
		}
	}
	if !hasTCP && !hasUDP {
		hasTCP = true
		ep.Protocols = append(ep.Protocols, gateonv1.EntryPoint_TCP_PROTO)
	}
	addr := ep.Address
	isHTTPPort := strings.HasSuffix(addr, ":80") || strings.HasSuffix(addr, ":443") ||
		strings.HasSuffix(addr, ":8080") || strings.HasSuffix(addr, ":8443") || strings.Contains(addr, "http")
	tlsEnabled := ep.Tls != nil && ep.Tls.Enabled
	if hasTCP {
		if tlsEnabled || isHTTPPort {
			ep.Type = gateonv1.EntryPoint_HTTP
		} else {
			ep.Type = gateonv1.EntryPoint_TCP
		}
	} else if hasUDP {
		if tlsEnabled || isHTTPPort {
			ep.Type = gateonv1.EntryPoint_HTTP3
		} else {
			ep.Type = gateonv1.EntryPoint_UDP
		}
	}
	if hasTCP && hasUDP && (tlsEnabled || isHTTPPort) {
		ep.Type = gateonv1.EntryPoint_HTTP3
	}
}
