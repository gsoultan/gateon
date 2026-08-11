// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/proxy"
	"github.com/gsoultan/gateon/internal/middleware"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// l4Invalidator invalidates L4 resolver cache for routes.
type l4Invalidator interface {
	InvalidateForRoute(rt *gateonv1.Route)
}

// serverProxyInvalidator implements proxy.Invalidator.
// Server observes domain events and invalidates proxy + L4 cache (Observer pattern).
type serverProxyInvalidator struct {
	server     *Server
	l4Resolver l4Invalidator
	routeStore config.RouteStore
}

// NewServerProxyInvalidator creates a ProxyInvalidator that delegates to Server.
func NewServerProxyInvalidator(s *Server, l4Resolver l4Invalidator, routeStore config.RouteStore) proxy.Invalidator {
	return &serverProxyInvalidator{server: s, l4Resolver: l4Resolver, routeStore: routeStore}
}

// InvalidateRoute implements proxy.Invalidator.
func (p *serverProxyInvalidator) InvalidateRoute(id string) {
	p.server.InvalidateRouteProxy(id)
	if p.l4Resolver != nil && p.routeStore != nil {
		if rt, ok := p.routeStore.Get(context.Background(), id); ok && rt != nil {
			p.l4Resolver.InvalidateForRoute(rt)
		}
	}
}

// InvalidateRoutes implements proxy.Invalidator.
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

// InvalidateTLS implements proxy.Invalidator.
func (p *serverProxyInvalidator) InvalidateTLS() {
	InvalidateTLSCache()
	if p.server.TLSManager != nil {
		p.server.TLSManager.UpdateConfig(BuildGtlsConfig(p.server))
		p.server.TLSManager.ClearCache()
	}
}

// InvalidateWAF implements proxy.Invalidator.
func (p *serverProxyInvalidator) InvalidateWAF() {
	middleware.InvalidateWAFCache()
	// Force rebuild of all proxies to pick up new WAF instances/rules
	p.server.InvalidateRouteProxies(func(r *gateonv1.Route) bool { return true })
}

// WafToProxyInvalidator bridges waf.Store.Invalidator to proxy.Invalidator.
type WafToProxyInvalidator struct {
	ProxyInv proxy.Invalidator
}

func (b *WafToProxyInvalidator) Invalidate() {
	if b.ProxyInv != nil {
		b.ProxyInv.InvalidateWAF()
	}
}
