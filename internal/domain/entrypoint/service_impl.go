// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

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
	store       config.EntryPointStore
	invalidator proxy.Invalidator
	logger      logger.Logger
}

// NewService creates an EntryPoint Service.
func NewService(store config.EntryPointStore, invalidator proxy.Invalidator, l logger.Logger) Service {
	return &serviceImpl{store: store, invalidator: invalidator, logger: l}
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
	if err := s.store.Update(ctx, ep); err != nil {
		return err
	}
	Invalidate(s.invalidator, ep)
	return nil
}

// Invalidate discards the cached work an entrypoint change invalidates.
//
// Exported because saving an entrypoint is reachable from two transports and
// only one of them did this: internal/api invalidated, and this package -- the
// one the dashboard's PUT /v1/entryPoints goes through -- did not. So an
// operator tightening an entrypoint's TLS settings in the dashboard got a
// success and a listener still negotiating with the old configuration until the
// process restarted. That is the failure mode where a security setting reads as
// applied and is not.
//
// Global routes are included deliberately: a route with no entrypoints listed
// serves on every one of them, so a change here affects it too.
func Invalidate(inv proxy.Invalidator, ep *gateonv1.EntryPoint) {
	if inv == nil || ep == nil {
		return
	}
	inv.InvalidateRoutes(func(r *gateonv1.Route) bool {
		if len(r.Entrypoints) == 0 {
			return true // serves on every entrypoint, including this one
		}
		for _, id := range r.Entrypoints {
			if id == ep.Id {
				return true
			}
		}
		return false
	})
	if ep.Tls != nil {
		inv.InvalidateTLS()
	}
}

// DeleteEntryPoint removes the entrypoint.
// DeleteEntryPoint removes the entrypoint and deliberately leaves every route
// that names it alone.
//
// Deleting a service clears its id from the routes that referenced it, and the
// symmetry is tempting. It would be a hole. Route.Entrypoints is a filter that
// is only applied when it is non-empty -- the router reads
// `if len(rt.Entrypoints) > 0` -- so an empty list means the route serves on
// *every* entrypoint. Clearing the reference on a route bound solely to an
// internal listener would publish it on the public one, and the operator's last
// action was deleting something, which is the last place anyone looks for a
// route that suddenly became reachable.
//
// Leaving the id dangling fails closed instead: the filter no longer matches any
// live entrypoint, so the route stops being served. It goes quiet rather than
// going public, and quiet is the recoverable half.
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
