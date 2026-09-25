// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/internal/security/reputation"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ProxyCache caches route proxy handlers and manages their lifecycle.
// Single responsibility: proxy creation, caching, and invalidation.
type ProxyCache struct {
	routeStore    config.RouteStore
	serviceStore  config.ServiceStore
	mwStore       config.MiddlewareStore
	globalStore   config.GlobalConfigStore
	ebpfManager   ebpf.Manager
	reputation    *reputation.IPReputationStore
	redisClient   redis.Client
	proxies       atomic.Value // map[string]http.Handler
	proxyHandlers atomic.Value // map[string]*proxy.ProxyHandler
	mu            sync.Mutex   // only for writes
	sf            singleflight.Group
	// epoch is bumped, under mu, by every change that removes cached chains.
	// A build records it when it starts and caches its result only if it is
	// unchanged, which is how a chain compiled from configuration that changed
	// mid-build is kept out of the cache without holding mu across the build.
	epoch atomic.Uint64
	// refusalRetry is how long a refused chain is served before the next
	// request, or the next Sync, builds the route again.
	refusalRetry time.Duration
}

// defaultRefusalRetry bounds how long a route stays refused after the
// dependency that failed its build has come back. Sync runs every 30 seconds,
// so a route with no traffic recovers within that; one with traffic within
// this.
const defaultRefusalRetry = 15 * time.Second

// maxBuildAttempts caps how often a build is thrown away because an
// invalidation landed while it ran, before the last attempt is made under mu,
// which holds invalidations off and so always completes.
const maxBuildAttempts = 3

// NewProxyCache creates a proxy cache with the given dependencies.
func NewProxyCache(
	routeStore config.RouteStore,
	serviceStore config.ServiceStore,
	mwStore config.MiddlewareStore,
	redisClient redis.Client,
	globalStore config.GlobalConfigStore,
	ebpfManager ebpf.Manager,
	ipReputation any,
) *ProxyCache {
	rep, _ := ipReputation.(*reputation.IPReputationStore)
	c := &ProxyCache{
		routeStore:   routeStore,
		serviceStore: serviceStore,
		mwStore:      mwStore,
		globalStore:  globalStore,
		ebpfManager:  ebpfManager,
		reputation:   rep,
		redisClient:  redisClient,
		refusalRetry: defaultRefusalRetry,
	}
	c.proxies.Store(make(map[string]http.Handler))
	c.proxyHandlers.Store(make(map[string]*proxy.ProxyHandler))
	return c
}

func transportConfigFromGlobal(gc *gateonv1.GlobalConfig) *proxy.TransportConfig {
	if gc == nil || gc.Transport == nil {
		return nil
	}
	t := gc.Transport
	cfg := &proxy.TransportConfig{}
	if t.MaxIdleConns > 0 {
		cfg.MaxIdleConns = int(t.MaxIdleConns)
	}
	if t.MaxIdleConnsPerHost > 0 {
		cfg.MaxIdleConnsPerHost = int(t.MaxIdleConnsPerHost)
	}
	if t.IdleConnTimeoutSeconds > 0 {
		cfg.IdleConnTimeout = time.Duration(t.IdleConnTimeoutSeconds) * time.Second
	}
	return cfg
}

// Count returns the number of active proxies in the cache.
func (c *ProxyCache) Count() int {
	m := c.proxies.Load().(map[string]http.Handler)
	return len(m)
}

// GetOrCreate returns a cached proxy handler for the route or creates one.
func (c *ProxyCache) GetOrCreate(rt *gateonv1.Route) http.Handler {
	// Lock-free read path
	m := c.proxies.Load().(map[string]http.Handler)
	if h, ok := m[rt.Id]; ok && !c.retryDue(h) {
		return h
	}

	// Use singleflight to prevent thundering herd during cold start or invalidation
	res, _, _ := c.sf.Do(rt.Id, func() (any, error) {
		return c.build(rt), nil
	})
	h, _ := res.(http.Handler)
	return h
}

// retryDue reports whether h is a refused chain old enough to build again.
func (c *ProxyCache) retryDue(h http.Handler) bool {
	rc, ok := h.(*router.RefusedChain)
	return ok && time.Since(rc.BuiltAt()) >= c.refusalRetry
}

// build compiles rt's chain without holding mu. It used to hold it throughout,
// so one slow build — a WAF compiling its rules, an identity provider that
// never answered — stalled the first request of every other route and every
// invalidation, which after a global change meant every route in the gateway.
// The lock was also what kept a build from caching configuration that changed
// while it ran; the epoch does that now.
func (c *ProxyCache) build(rt *gateonv1.Route) http.Handler {
	for range maxBuildAttempts - 1 {
		epoch := c.epoch.Load()
		if h, ok := c.cached(rt.Id); ok {
			return h
		}
		h, ph := c.compile(c.current(rt))
		if h == nil || c.storeIfCurrent(rt.Id, h, ph, epoch) {
			return h
		}
		// An invalidation landed mid-build, so this chain reflects
		// configuration that has since changed. Discard it and build again.
		ph.Close()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, ok := c.cached(rt.Id); ok {
		return h
	}
	h, ph := c.compile(c.current(rt))
	if h != nil {
		c.storeLocked(rt.Id, h, ph)
	}
	return h
}

// current returns the route as it is stored now, read after the build has
// recorded the epoch. The caller selected its copy before asking, which can be
// before an edit whose invalidation has already run; compiling that copy would
// cache the old route under the new epoch, and serve it until the next edit.
// A route missing from the store (deleted mid-request) is built as given and
// left for Sync to collect.
func (c *ProxyCache) current(rt *gateonv1.Route) *gateonv1.Route {
	if fresh, ok := c.routeStore.Get(context.Background(), rt.Id); ok && fresh != nil {
		return fresh
	}
	return rt
}

// cached returns the route's chain if one is cached and not a refusal due for
// a retry.
func (c *ProxyCache) cached(id string) (http.Handler, bool) {
	m := c.proxies.Load().(map[string]http.Handler)
	h, ok := m[id]
	if !ok || c.retryDue(h) {
		return nil, false
	}
	return h, true
}

// compile builds the proxy handler and the middleware chain around it.
func (c *ProxyCache) compile(rt *gateonv1.Route) (http.Handler, *proxy.ProxyHandler) {
	var transportCfg *proxy.TransportConfig
	if c.globalStore != nil {
		if gc := c.globalStore.Get(context.Background()); gc != nil {
			transportCfg = transportConfigFromGlobal(gc)
		}
	}

	stripCORS := router.RouteHasMiddlewareType(context.Background(), rt, c.mwStore, "cors") ||
		router.RouteHasMiddlewareType(context.Background(), rt, c.mwStore, "grpcweb")
	pHandler := proxy.NewProxyHandlerBuilder(rt, c.serviceStore, nil).
		SetTransportConfig(transportCfg).
		SetStripCORS(stripCORS).
		Build()

	h := router.ApplyRouteMiddlewares(pHandler, rt, c.redisClient, c.mwStore, c.globalStore, c.ebpfManager, c.reputation)
	if h == nil {
		pHandler.Close()
		return nil, nil
	}
	return h, pHandler
}

// storeIfCurrent caches a chain unless an invalidation has landed since the
// build that produced it began.
func (c *ProxyCache) storeIfCurrent(id string, h http.Handler, ph *proxy.ProxyHandler, epoch uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epoch.Load() != epoch {
		return false
	}
	c.storeLocked(id, h, ph)
	return true
}

// storeLocked caches a chain, draining the proxy handler it replaces — a
// refused chain being retried still owns one.
func (c *ProxyCache) storeLocked(id string, h http.Handler, ph *proxy.ProxyHandler) {
	m := c.proxies.Load().(map[string]http.Handler)
	newProxies := maps.Clone(m)
	if newProxies == nil {
		newProxies = make(map[string]http.Handler)
	}
	newProxies[id] = h
	c.proxies.Store(newProxies)

	phMap := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)
	old := phMap[id]
	newPhMap := maps.Clone(phMap)
	if newPhMap == nil {
		newPhMap = make(map[string]*proxy.ProxyHandler)
	}
	newPhMap[id] = ph
	c.proxyHandlers.Store(newPhMap)
	if old != nil && old != ph {
		go old.DrainAndClose(drainTimeout)
	}
}

// InvalidateRoute removes the cached proxy for the given route ID.
func (c *ProxyCache) InvalidateRoute(routeID string) {
	if routeID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidateLocked(routeID)
}

// InvalidateRoutes removes cached proxies for routes matching the strategy.
func (c *ProxyCache) InvalidateRoutes(strategy func(*gateonv1.Route) bool) {
	if strategy == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rt := range c.routeStore.List(context.Background()) {
		if strategy(rt) {
			c.invalidateLocked(rt.Id)
		}
	}
}

const drainTimeout = 30 * time.Second

func (c *ProxyCache) invalidateLocked(id string) {
	// Bumped even when nothing is cached: the route may be mid-build, and that
	// build must not cache what it compiled from the configuration being
	// replaced.
	c.epoch.Add(1)
	phMap := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)
	m := c.proxies.Load().(map[string]http.Handler)

	ph, ok1 := phMap[id]
	old, ok2 := m[id]

	if !ok1 && !ok2 {
		return
	}

	newM := maps.Clone(m)
	delete(newM, id)
	c.proxies.Store(newM)

	newPhMap := maps.Clone(phMap)
	delete(newPhMap, id)
	c.proxyHandlers.Store(newPhMap)

	if ph != nil {
		go ph.DrainAndClose(drainTimeout)
		return
	}
	type closer interface{ Close() }
	if old != nil {
		if cl, ok := old.(closer); ok {
			cl.Close()
		}
	}
}

// GetRouteStats returns target stats for a route, or nil if not found.
func (c *ProxyCache) GetRouteStats(routeID string) []proxy.TargetStats {
	phMap := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)
	ph, ok := phMap[routeID]
	if !ok {
		rt, exists := c.routeStore.Get(context.Background(), routeID)
		if !exists || rt == nil {
			return nil
		}
		_ = c.GetOrCreate(rt)
		phMap = c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)
		ph = phMap[routeID]
	}
	if ph == nil {
		return nil
	}
	return ph.GetStats()
}

// Purge clears all cached proxies.
func (c *ProxyCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.epoch.Add(1)
	handlers := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)
	for _, ph := range handlers {
		if ph != nil {
			go ph.DrainAndClose(drainTimeout)
		}
	}

	c.proxies.Store(make(map[string]http.Handler))
	c.proxyHandlers.Store(make(map[string]*proxy.ProxyHandler))
	logger.L.LogInfo("proxy cache purged due to resource pressure")
}

// Sync runs periodic proxy cache maintenance: pre-warms new routes and cleans up orphans.
func (c *ProxyCache) Sync() {
	// 1. Pre-warm: Ensure all active routes have a compiled proxy handler.
	// This eliminates the first-request latency penalty and validates configs early.
	for _, rt := range c.routeStore.List(context.Background()) {
		if !rt.Disabled {
			_ = c.GetOrCreate(rt)
		}
	}

	// 2. Cleanup: Remove cached proxies for routes that no longer exist, and
	// the circuit breakers of route labels that no longer exist.
	c.mu.Lock()
	defer c.mu.Unlock()

	proxies := c.proxies.Load().(map[string]http.Handler)
	handlers := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)

	activeRoutes := make(map[string]bool)
	liveLabels := make(map[string]bool)
	for _, rt := range c.routeStore.List(context.Background()) {
		activeRoutes[rt.Id] = true
		liveLabels[router.RouteLabel(rt)] = true
	}
	middleware.RetainCircuitBreakers(liveLabels)

	orphans := make([]string, 0)
	for id := range proxies {
		if !activeRoutes[id] {
			orphans = append(orphans, id)
		}
	}

	if len(orphans) > 0 {
		c.epoch.Add(1)
		newProxies := maps.Clone(proxies)
		newHandlers := maps.Clone(handlers)
		for _, id := range orphans {
			delete(newProxies, id)
			if ph, ok := newHandlers[id]; ok {
				delete(newHandlers, id)
				go ph.DrainAndClose(drainTimeout)
			}
		}
		c.proxies.Store(newProxies)
		c.proxyHandlers.Store(newHandlers)
	}
}
