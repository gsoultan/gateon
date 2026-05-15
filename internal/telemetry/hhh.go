package telemetry

import (
	"net/netip"
	"slices"
	"sync"
)

// HHHCounter implements a Hierarchical Heavy Hitters algorithm.
// It tracks request counts at different CIDR levels (/8, /16, /24, /32 for IPv4)
// to identify malicious subnets.
type HHHCounter struct {
	mu     sync.RWMutex
	counts map[netip.Prefix]int
	total  int
}

type HeavyHitter struct {
	Network    string  `json:"network"`
	Count      int     `json:"count"`
	Percentage float64 `json:"percentage"`
}

// NewHHHCounter creates a new HHHCounter.
func NewHHHCounter() *HHHCounter {
	return &HHHCounter{
		counts: make(map[netip.Prefix]int),
	}
}

// Add tracks an IP address and updates its hierarchy.
func (c *HHHCounter) Add(ipStr string) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.total++

	if addr.Is4() {
		for _, p := range []int{8, 16, 24, 32} {
			prefix := netip.PrefixFrom(addr, p).Masked()
			c.counts[prefix]++
		}
	} else if addr.Is6() {
		for _, p := range []int{32, 48, 64, 128} {
			prefix := netip.PrefixFrom(addr, p).Masked()
			c.counts[prefix]++
		}
	}
}

// GetHeavyHitters returns subnets that exceed the given threshold.
// It uses a simplified Hierarchical Heavy Hitters logic (conditioned frequency).
func (c *HHHCounter) GetHeavyHitters(threshold int) []HeavyHitter {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.total == 0 {
		return nil
	}

	// Copy counts to work with conditioned frequencies
	condFreq := make(map[netip.Prefix]int, len(c.counts))
	for k, v := range c.counts {
		condFreq[k] = v
	}

	var hitters []HeavyHitter
	ipv4Levels := []int{32, 24, 16, 8}
	ipv6Levels := []int{128, 64, 48, 32}

	processLevels := func(levels []int) {
		for _, l := range levels {
			for p, freq := range condFreq {
				if p.Bits() != l {
					continue
				}

				if freq >= threshold {
					hitters = append(hitters, HeavyHitter{
						Network:    p.String(),
						Count:      freq,
						Percentage: float64(freq) / float64(c.total) * 100,
					})

					// Subtract this frequency from all parent prefixes
					parent := p
					for parent.Bits() > 0 {
						// Find the next level up
						nextLen := -1
						for _, lvl := range levels {
							if lvl < parent.Bits() {
								if nextLen == -1 || lvl > nextLen {
									nextLen = lvl
								}
							}
						}
						if nextLen == -1 {
							break
						}

						parent = netip.PrefixFrom(parent.Addr(), nextLen).Masked()
						if _, ok := condFreq[parent]; ok {
							condFreq[parent] -= freq
						}
					}
				}
			}
		}
	}

	processLevels(ipv4Levels)
	processLevels(ipv6Levels)

	// Sort by count descending
	slices.SortFunc(hitters, func(a, b HeavyHitter) int {
		return b.Count - a.Count
	})

	return hitters
}

// Clear resets the counter.
func (c *HHHCounter) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = make(map[netip.Prefix]int)
	c.total = 0
}
