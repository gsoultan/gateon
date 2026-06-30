package server

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/ebpf"
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

		transportCfg := transportConfigFromGlobal(c.globalStore.Get(context.Background()))
		stripCORS := router.RouteHasMiddlewareType(context.Background(), rt, c.mwStore, "cors") ||
			router.RouteHasMiddlewareType(context.Background(), rt, c.mwStore, "grpcweb")
		pHandler := proxy.NewProxyHandlerBuilder(rt, c.serviceStore, nil).
			SetTransportConfig(transportCfg).
			SetStripCORS(stripCORS).
			Build()

		h := router.ApplyRouteMiddlewares(pHandler, rt, c.redisClient, c.mwStore, c.globalStore, c.ebpfManager, c.reputation)

		// Atomic update: swap maps
		newProxies := make(map[string]http.Handler, len(m)+1)
		for k, v := range m {
			newProxies[k] = v
		}
		newProxies[rt.Id] = h
		c.proxies.Store(newProxies)

		phMap := c.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)
		newPhMap := make(map[string]*proxy.ProxyHandler, len(phMap)+1)
		for k, v := range phMap {
			newPhMap[k] = v
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

	ph := phMap[id]
	old := m[id]

	if ph == nil && old == nil {
		return
	}

	newM := make(map[string]http.Handler, len(m))
	for k, v := range m {
		if k != id {
			newM[k] = v
		}
	}
	c.proxies.Store(newM)

	newPhMap := make(map[string]*proxy.ProxyHandler, len(phMap))
	for k, v := range phMap {
		if k != id {
			newPhMap[k] = v
		}
	}
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

// Sync runs periodic proxy cache maintenance (e.g. metrics).
func (c *ProxyCache) Sync() {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.proxies.Load().(map[string]http.Handler)
	_ = len(m)
}
