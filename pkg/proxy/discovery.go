// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package proxy

import (
	"context"
	"time"

	"github.com/gsoultan/gateon/internal/discovery"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

const (
	discoveryInterval       = 30 * time.Second
	discoveryResolveTimeout = 10 * time.Second
)

func (h *ProxyHandler) runDiscovery() {
	if h.discoveryURL == "" {
		return
	}
	ticker := time.NewTicker(discoveryInterval)
	defer ticker.Stop()

	resolver := discovery.NewResolver()

	for {
		select {
		case <-ticker.C:
			targets := h.resolveTargets(resolver)
			if len(targets) > 0 {
				h.applyDiscoveredTargets(targets)
			}
		case <-h.stopDiscovery:
			return
		}
	}
}

// resolveTargets performs a single discovery lookup. The timeout keeps a
// hanging resolver from making the discovery loop unresponsive to shutdown.
func (h *ProxyHandler) resolveTargets(resolver *discovery.Resolver) []*gateonv1.Target {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryResolveTimeout)
	defer cancel()

	targets, err := resolver.Resolve(ctx, h.discoveryURL)
	if err != nil {
		return nil
	}
	return targets
}

// applyDiscoveredTargets swaps in the freshly discovered target set and
// releases the resources still held by the targets that disappeared.
func (h *ProxyHandler) applyDiscoveredTargets(targets []*gateonv1.Target) {
	previous := h.currentTargetURLs()

	h.lb.UpdateWeightedTargets(targets)

	active := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if t != nil {
			active[t.Url] = struct{}{}
		}
	}

	for url := range previous {
		if _, stillActive := active[url]; !stillActive {
			h.retireTargetMetrics(url)
		}
	}

	h.transportFactory.PruneExcept(active)
}

func (h *ProxyHandler) currentTargetURLs() map[string]struct{} {
	stats := h.lb.GetStats()
	urls := make(map[string]struct{}, len(stats))
	for _, s := range stats {
		urls[s.URL] = struct{}{}
	}
	return urls
}

// retireTargetMetrics drops the per-target time series of a backend that is no
// longer part of the service, preventing unbounded Prometheus cardinality
// growth on clusters with churning backends.
func (h *ProxyHandler) retireTargetMetrics(url string) {
	telemetry.TargetHealth.DeleteLabelValues(h.RouteName(), url)
	telemetry.ActiveConnections.DeleteLabelValues(url)
}
