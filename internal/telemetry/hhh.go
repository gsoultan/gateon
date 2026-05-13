package telemetry

import (
	"fmt"
	"net"
	"sync"
)

// HHHCounter implements a simplified Hierarchical Heavy Hitters algorithm.
// It tracks request counts at different CIDR levels (/8, /16, /24, /32)
// to identify malicious subnets.
type HHHCounter struct {
	mu     sync.RWMutex
	counts map[string]int
}

// NewHHHCounter creates a new HHHCounter.
func NewHHHCounter() *HHHCounter {
	return &HHHCounter{
		counts: make(map[string]int),
	}
}

// Add tracks an IP address and updates its hierarchy.
func (c *HHHCounter) Add(ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return // IPv6 not implemented for simplicity in this HHH
	}

	prefixes := []int{8, 16, 24, 32}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, p := range prefixes {
		mask := net.CIDRMask(p, 32)
		network := ipv4.Mask(mask)
		key := fmt.Sprintf("%s/%d", network.String(), p)
		c.counts[key]++
	}
}

// GetHeavyHitters returns subnets that exceed the given threshold.
func (c *HHHCounter) GetHeavyHitters(threshold int) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var hitters []string
	for subnet, count := range c.counts {
		if count >= threshold {
			hitters = append(hitters, fmt.Sprintf("%s (%d requests)", subnet, count))
		}
	}
	return hitters
}

// Clear resets the counter.
func (c *HHHCounter) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = make(map[string]int)
}
