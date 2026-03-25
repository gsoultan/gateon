// Package l4 provides production-ready L4 (TCP/UDP) proxy with load balancing and health checks.
package l4

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Resolver resolves L4 backends from Route → Service. Supports caching and invalidation.
type Resolver struct {
	routeStore   config.RouteStore
	serviceStore config.ServiceStore
	mu           sync.RWMutex
	tcpPools     map[string]*cachedTCPPool
	udpProxies   map[string]*cachedUDPProxy
}

// cachedTCPPool holds a pool and its config hash for invalidation.
type cachedTCPPool struct {
	pool *TCPBackendPool
	hash uint64
}

// cachedUDPProxy holds a UDP proxy and its config hash.
type cachedUDPProxy struct {
	proxy *UDPSessionProxy
	hash  uint64
}

// NewResolver creates an L4 resolver that fetches backends from routes and services.
func NewResolver(routeStore config.RouteStore, serviceStore config.ServiceStore) *Resolver {
	return &Resolver{
		routeStore:   routeStore,
		serviceStore: serviceStore,
		tcpPools:     make(map[string]*cachedTCPPool),
		udpProxies:   make(map[string]*cachedUDPProxy),
	}
}

// SelectL4Route finds the best L4 route for the given entrypoint and type (tcp/udp).
func SelectL4Route(ctx context.Context, epID string, routeType string, routeStore config.RouteStore) *gateonv1.Route {
	rtLower := strings.ToLower(routeType)
	routes := routeStore.List(ctx)
	var best *gateonv1.Route
	for _, rt := range routes {
		if rt.Disabled || rt.ServiceId == "" {
			continue
		}
		if strings.ToLower(rt.Type) != rtLower {
			continue
		}
		for _, e := range rt.Entrypoints {
			if e == epID {
				if best == nil || rt.Priority > best.Priority {
					best = rt
				}
				break
			}
		}
	}
	return best
}

// BackendsFromService extracts L4 backend addresses from a service.
// For tcp/udp backend_type, targets use url as "host:port".
func BackendsFromService(svc *gateonv1.Service) []string {
	if svc == nil {
		return nil
	}
	var addrs []string
	for _, t := range svc.WeightedTargets {
		addr := toL4Addr(t.Url)
		if addr != "" {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func toL4Addr(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	// L4 targets use host:port. Strip http(s):// prefix if present (legacy).
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "tcp://")
	if url == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(url); err == nil {
		return net.JoinHostPort(host, port)
	}
	return ""
}

// ConfigFromRouteService builds L4Config from a route and its service.
func ConfigFromRouteService(rt *gateonv1.Route, svc *gateonv1.Service) *L4Config {
	if rt == nil || svc == nil {
		return nil
	}
	addrs := BackendsFromService(svc)
	if len(addrs) == 0 {
		return nil
	}
	lb := svc.LoadBalancerPolicy
	if lb == "" {
		lb = "round_robin"
	}
	interval := int(svc.L4HealthCheckIntervalMs)
	if interval <= 0 {
		interval = 10000
	}
	timeout := int(svc.L4HealthCheckTimeoutMs)
	if timeout <= 0 {
		timeout = 3000
	}
	sessionTimeout := int(svc.L4UdpSessionTimeoutS)
	if sessionTimeout <= 0 {
		sessionTimeout = 60
	}
	return &L4Config{
		Backends:            addrs,
		LoadBalancer:        lb,
		HealthCheckInterval: interval,
		HealthCheckTimeout:  timeout,
		UDPSessionTimeout:   sessionTimeout,
		ProxyProtocol:       svc.L4ProxyProtocol,
	}
}

// ResolveTCP resolves the TCP backend pool for an L4 entrypoint from Route → Service.
func (r *Resolver) ResolveTCP(ep *gateonv1.EntryPoint) *TCPBackendPool {
	cfg := r.resolveConfig(ep, "tcp")
	if cfg == nil || len(cfg.Backends) == 0 {
		return nil
	}
	hash := configHash(cfg)
	key := ep.Id
	r.mu.RLock()
	if cached, ok := r.tcpPools[key]; ok && cached.hash == hash {
		p := cached.pool
		r.mu.RUnlock()
		return p
	}
	r.mu.RUnlock()

	pool := NewTCPBackendPool(cfg.Backends, cfg.LoadBalancer, cfg.HealthCheckInterval, cfg.HealthCheckTimeout, cfg.ProxyProtocol)
	if pool != nil && cfg.HealthCheckInterval > 0 {
		go pool.StartHealthChecks()
	}
	r.mu.Lock()
	old := r.tcpPools[key]
	if old != nil && old.pool != nil {
		old.pool.Stop()
	}
	r.tcpPools[key] = &cachedTCPPool{pool: pool, hash: hash}
	r.mu.Unlock()
	return pool
}

// ResolveUDP resolves the UDP proxy for an L4 entrypoint from Route → Service.
func (r *Resolver) ResolveUDP(ep *gateonv1.EntryPoint) *UDPSessionProxy {
	cfg := r.resolveConfig(ep, "udp")
	if cfg == nil || len(cfg.Backends) == 0 {
		return nil
	}
	hash := configHash(cfg)
	key := ep.Id
	r.mu.RLock()
	if cached, ok := r.udpProxies[key]; ok && cached.hash == hash {
		p := cached.proxy
		r.mu.RUnlock()
		return p
	}
	r.mu.RUnlock()

	proxy := NewUDPSessionProxy(cfg.Backends, cfg.LoadBalancer, cfg.UDPSessionTimeout)
	r.mu.Lock()
	old := r.udpProxies[key]
	if old != nil && old.proxy != nil {
		old.proxy.Stop()
	}
	r.udpProxies[key] = &cachedUDPProxy{proxy: proxy, hash: hash}
	r.mu.Unlock()
	return proxy
}

func (r *Resolver) resolveConfig(ep *gateonv1.EntryPoint, routeType string) *L4Config {
	rt := SelectL4Route(context.Background(), ep.Id, routeType, r.routeStore)
	if rt == nil {
		return nil
	}
	svc, ok := r.serviceStore.Get(context.Background(), rt.ServiceId)
	if !ok {
		return nil
	}
	bt := strings.ToLower(svc.BackendType)
	want := strings.ToLower(routeType)
	if bt != want {
		return nil
	}
	return ConfigFromRouteService(rt, svc)
}

func configHash(cfg *L4Config) uint64 {
	h := fnv.New64a()
	proxy := "0"
	if cfg.ProxyProtocol {
		proxy = "1"
	}
	parts := append([]string{cfg.LoadBalancer, fmt.Sprintf("%d", cfg.HealthCheckInterval),
		fmt.Sprintf("%d", cfg.HealthCheckTimeout), fmt.Sprintf("%d", cfg.UDPSessionTimeout), proxy},
		cfg.Backends...)
	sort.Strings(parts)
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
	}
	return h.Sum64()
}

// InvalidateEntrypoint clears the cache for the given entrypoint (call when routes/services change).
func (r *Resolver) InvalidateEntrypoint(epID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.tcpPools[epID]; c != nil && c.pool != nil {
		c.pool.Stop()
	}
	delete(r.tcpPools, epID)
	if c := r.udpProxies[epID]; c != nil && c.proxy != nil {
		c.proxy.Stop()
	}
	delete(r.udpProxies, epID)
}

// InvalidateForRoute invalidates all entrypoints referenced by the route.
func (r *Resolver) InvalidateForRoute(rt *gateonv1.Route) {
	if rt == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, epID := range rt.Entrypoints {
		if c := r.tcpPools[epID]; c != nil && c.pool != nil {
			c.pool.Stop()
		}
		delete(r.tcpPools, epID)
		if c := r.udpProxies[epID]; c != nil && c.proxy != nil {
			c.proxy.Stop()
		}
		delete(r.udpProxies, epID)
	}
}

// InvalidateForService invalidates all entrypoints whose routes use this service.
func (r *Resolver) InvalidateForService(serviceID string) {
	routes := r.routeStore.List(context.Background())
	for _, rt := range routes {
		if rt.ServiceId == serviceID {
			r.InvalidateForRoute(rt)
		}
	}
}
