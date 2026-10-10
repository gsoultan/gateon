// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/router/rule"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serviceImpl implements Service.
type serviceImpl struct {
	store       config.RouteStore
	invalidator proxy.Invalidator
	logger      logger.Logger
	guards      []SaveGuard
}

// NewService creates a Route Service. The optional SaveGuards each refuse
// saves of their own kind -- binding a credential-injecting middleware (ADR
// 0038), a tls_binding middleware on an entrypoint without TLS (ADR 0046) --
// and all of them run; a build that passes none is unguarded, which is why
// every caller that serves the management API passes them.
func NewService(store config.RouteStore, invalidator proxy.Invalidator, l logger.Logger, guards ...SaveGuard) Service {
	s := &serviceImpl{store: store, invalidator: invalidator, logger: l}
	for _, g := range guards {
		if g != nil {
			s.guards = append(s.guards, g)
		}
	}
	return s
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
	if err := ValidateRule(rt); err != nil {
		return err
	}
	if err := ValidateStreamMode(rt); err != nil {
		return err
	}
	if rt.Id == "" {
		rt.Id = uuid.NewString()
	}
	// Authorized after the id is assigned, so the guard can read the stored
	// route (an update) or find none (a create), and before persistence, so a
	// refusal changes nothing.
	for _, g := range s.guards {
		if err := g.AuthorizeRouteSave(ctx, rt); err != nil {
			return err
		}
	}
	if err := s.nameIsFree(ctx, rt); err != nil {
		return err
	}
	if err := s.store.Update(ctx, rt); err != nil {
		return err
	}
	s.invalidator.InvalidateRoute(rt.Id)
	return nil
}

// ErrInvalidRule is returned for a route whose rule does not parse. The error
// it wraps says at which character and why.
var ErrInvalidRule = errors.New("invalid route rule")

// ValidateRule refuses a route whose rule the router could not read in full
// (ADR 0043). The router used to read such a rule as one with no condition,
// which matches every request: a typo on one route took the entrypoint's
// traffic from the routes that did describe it, and with it their auth and
// WAF. It is checked here, on the save every transport and config import go
// through, so no writer can store one; the router still treats a stored rule
// it cannot read as matching nothing.
//
// A TCP or UDP route is chosen by its entrypoint, so its rule may be empty;
// one it does have must still parse, because the HTTP router reads it too.
func ValidateRule(rt *gateonv1.Route) error {
	if strings.TrimSpace(rt.GetRule()) == "" {
		if t := strings.ToLower(rt.GetType()); t == "tcp" || t == "udp" {
			return nil
		}
		return errors.New("missing rule (required for http/grpc routes)")
	}
	if _, err := rule.Parse(rt.GetRule()); err != nil {
		return fmt.Errorf("%w %w", ErrInvalidRule, err)
	}
	return nil
}

// ErrInvalidStreamMode is returned for a route whose stream_mode names no
// value the gateway knows.
var ErrInvalidStreamMode = errors.New("invalid route stream_mode")

// ValidateStreamMode refuses a stream_mode outside the enum (ADR 0064). The
// router reads an unknown value as auto, so storing one would save a setting
// that does nothing while the route list showed a number nobody chose.
func ValidateStreamMode(rt *gateonv1.Route) error {
	m := rt.GetStreamMode()
	if m.Descriptor().Values().ByNumber(m.Number()) == nil {
		return fmt.Errorf("%w: %d (want 0 auto, 1 always or 2 never)", ErrInvalidStreamMode, m)
	}
	return nil
}

// ErrRouteNameTaken is returned when a route would share its name with another.
var ErrRouteNameTaken = errors.New("route name is already in use")

// nameIsFree refuses a route whose label -- its name, or its ID when it has
// none, as router.RouteLabel defines it -- another route already has. The
// label is what a route's metrics, access logs and threat records carry, so
// two routes sharing one cannot be told apart in any of them; and until
// per-route state was keyed by ID, they shared a circuit breaker and Redis
// cache entries as well.
func (s *serviceImpl) nameIsFree(ctx context.Context, rt *gateonv1.Route) error {
	label := cmp.Or(rt.Name, rt.Id)
	for _, other := range s.store.List(ctx) {
		if other.Id != rt.Id && cmp.Or(other.Name, other.Id) == label {
			return fmt.Errorf("%w: route %s is already called %q", ErrRouteNameTaken, other.Id, label)
		}
	}
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
