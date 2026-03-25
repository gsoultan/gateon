package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/redis"
	"github.com/gsoultan/gateon/internal/router"
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
	redisClient   redis.Client
	proxies       map[string]http.Handler
	proxyHandlers map[string]*proxy.ProxyHandler
	mu            sync.RWMutex
}

// NewProxyCache creates a proxy cache with the given dependencies.
func NewProxyCache(
	routeStore config.RouteStore,
	serviceStore config.ServiceStore,
	mwStore config.MiddlewareStore,
	redisClient redis.Client,
	globalStore config.GlobalConfigStore,
) *ProxyCache {
	return &ProxyCache{
		routeStore:    routeStore,
		serviceStore:  serviceStore,
		mwStore:       mwStore,
		globalStore:   globalStore,
		redisClient:   redisClient,
		proxies:       make(map[string]http.Handler),
		proxyHandlers: make(map[string]*proxy.ProxyHandler),
	}
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

// GetOrCreate returns a cached proxy handler for the route or creates one.
func (c *ProxyCache) GetOrCreate(rt *gateonv1.Route) http.Handler {
	c.mu.RLock()
	h, ok := c.proxies[rt.Id]
	c.mu.RUnlock()
	if ok {
		return h
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, ok = c.proxies[rt.Id]; ok {
		return h
	}
	transportCfg := transportConfigFromGlobal(c.globalStore.Get(context.Background()))
	pHandler := proxy.NewProxyHandlerWithOpts(rt, c.serviceStore, nil, transportCfg)
	c.proxyHandlers[rt.Id] = pHandler
	h = router.ApplyRouteMiddlewares(pHandler, rt, c.redisClient, c.mwStore)
	c.proxies[rt.Id] = h
	return h
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
	ph := c.proxyHandlers[id]
	old := c.proxies[id]
	delete(c.proxies, id)
	delete(c.proxyHandlers, id)
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
	c.mu.RLock()
	ph, ok := c.proxyHandlers[routeID]
	c.mu.RUnlock()
	if !ok {
		rt, exists := c.routeStore.Get(context.Background(), routeID)
		if !exists || rt == nil {
			return nil
		}
		_ = c.GetOrCreate(rt)
		c.mu.RLock()
		ph = c.proxyHandlers[routeID]
		c.mu.RUnlock()
	}
	if ph == nil {
		return nil
	}
	return ph.GetStats()
}

// Sync runs periodic proxy cache maintenance (e.g. metrics).
func (c *ProxyCache) Sync() {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = len(c.proxies)
}
