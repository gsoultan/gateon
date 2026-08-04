// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package server

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
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
}

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
	if h, ok := m[rt.Id]; ok {
		return h
	}

	// Use singleflight to prevent thundering herd during cold start or invalidation
	res, _, _ := c.sf.Do(rt.Id, func() (any, error) {
		// Double check under write lock
		c.mu.Lock()
		defer c.mu.Unlock()

		m := c.proxies.Load().(map[string]http.Handler)
		if h, ok := m[rt.Id]; ok {
			return h, nil
		}

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
			return nil, fmt.Errorf("failed to apply route middlewares")
		}

		// Atomic update: swap maps
		newProxies := maps.Clone(m)
		if newProxies == nil {
			newProxies = make(map[string]http.Handler)
		}
		newProxies[rt.Id] = h
		c.proxies.Store(newProxies)

		phMap := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)
		newPhMap := maps.Clone(phMap)
		if newPhMap == nil {
			newPhMap = make(map[string]*proxy.ProxyHandler)
		}
		newPhMap[rt.Id] = pHandler
		c.proxyHandlers.Store(newPhMap)

		return h, nil
	})

	return res.(http.Handler)
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

	// 2. Cleanup: Remove cached proxies for routes that no longer exist.
	c.mu.Lock()
	defer c.mu.Unlock()

	proxies := c.proxies.Load().(map[string]http.Handler)
	handlers := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)

	activeRoutes := make(map[string]bool)
	for _, rt := range c.routeStore.List(context.Background()) {
		activeRoutes[rt.Id] = true
	}

	orphans := make([]string, 0)
	for id := range proxies {
		if !activeRoutes[id] {
			orphans = append(orphans, id)
		}
	}

	if len(orphans) > 0 {
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
