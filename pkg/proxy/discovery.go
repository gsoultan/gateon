package proxy

import (
	"context"
	"time"

	"github.com/gsoultan/gateon/internal/discovery"
)

func (h *ProxyHandler) runDiscovery() {
	if h.discoveryURL == "" {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	resolver := discovery.NewResolver()

	for {
		select {
		case <-ticker.C:
			targets, err := resolver.Resolve(context.Background(), h.discoveryURL)
			if err == nil && len(targets) > 0 {
				h.lb.UpdateWeightedTargets(targets)
			}
		case <-h.stopDiscovery:
			return
		}
	}
}
