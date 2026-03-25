package server

import (
	"context"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// l4Invalidator invalidates L4 resolver cache for routes.
type l4Invalidator interface {
	InvalidateForRoute(rt *gateonv1.Route)
}

// serverProxyInvalidator implements domain.ProxyInvalidator.
// Server observes domain events and invalidates proxy + L4 cache (Observer pattern).
type serverProxyInvalidator struct {
	server     *Server
	l4Resolver l4Invalidator
	routeStore config.RouteStore
}

// NewServerProxyInvalidator creates a ProxyInvalidator that delegates to Server.
func NewServerProxyInvalidator(s *Server, l4Resolver l4Invalidator, routeStore config.RouteStore) domain.ProxyInvalidator {
	return &serverProxyInvalidator{server: s, l4Resolver: l4Resolver, routeStore: routeStore}
}

// InvalidateRoute implements domain.ProxyInvalidator.
func (p *serverProxyInvalidator) InvalidateRoute(id string) {
	p.server.InvalidateRouteProxy(id)
	if p.l4Resolver != nil && p.routeStore != nil {
		if rt, ok := p.routeStore.Get(context.Background(), id); ok && rt != nil {
			p.l4Resolver.InvalidateForRoute(rt)
		}
	}
}

// InvalidateRoutes implements domain.ProxyInvalidator.
func (p *serverProxyInvalidator) InvalidateRoutes(strategy func(*gateonv1.Route) bool) {
	p.server.InvalidateRouteProxies(strategy)
	if p.l4Resolver != nil && p.routeStore != nil {
		for _, rt := range p.routeStore.List(context.Background()) {
			if strategy(rt) {
				p.l4Resolver.InvalidateForRoute(rt)
			}
		}
	}
}
