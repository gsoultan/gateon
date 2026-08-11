// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

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

	// Work on a copy: the conditioning below subtracts each hitter's frequency
	// from its parent prefixes, so a /24 that is heavy only because of one busy
	// /32 inside it does not also get reported.
	condFreq := make(map[netip.Prefix]int, len(c.counts))
	for k, v := range c.counts {
		condFreq[k] = v
	}

	var hitters []HeavyHitter
	hitters = append(hitters, c.hittersAtLevels(condFreq, ipv4PrefixLevels, false, threshold)...)
	hitters = append(hitters, c.hittersAtLevels(condFreq, ipv6PrefixLevels, true, threshold)...)

	slices.SortFunc(hitters, func(a, b HeavyHitter) int {
		return b.Count - a.Count
	})
	return hitters
}

// Prefix lengths examined for heavy hitters, most specific first. Walking them
// in this order is what makes the conditioning work: a child is credited before
// its frequency is removed from the parent.
var (
	ipv4PrefixLevels = []int{32, 24, 16, 8}
	ipv6PrefixLevels = []int{128, 64, 48, 32}
)

// hittersAtLevels collects the prefixes at the given levels whose conditioned
// frequency still clears threshold, subtracting each one it reports from its
// parents so the same traffic is not counted twice up the hierarchy.
func (c *HHHCounter) hittersAtLevels(condFreq map[netip.Prefix]int, levels []int, isV6 bool, threshold int) []HeavyHitter {
	var hitters []HeavyHitter
	for _, level := range levels {
		for p, freq := range condFreq {
			if p.Bits() != level || p.Addr().Is6() != isV6 || freq < threshold {
				continue
			}
			hitters = append(hitters, HeavyHitter{
				Network:    p.String(),
				Count:      freq,
				Percentage: float64(freq) / float64(c.total) * 100,
			})
			subtractFromParents(condFreq, p, freq, levels)
		}
	}
	return hitters
}

// subtractFromParents removes freq from every ancestor of p present in
// condFreq, walking one configured level at a time toward the root.
func subtractFromParents(condFreq map[netip.Prefix]int, p netip.Prefix, freq int, levels []int) {
	parent := p
	for parent.Bits() > 0 {
		next := nextLevelUp(levels, parent.Bits())
		if next < 0 {
			return
		}
		parent = netip.PrefixFrom(parent.Addr(), next).Masked()
		if _, ok := condFreq[parent]; ok {
			condFreq[parent] -= freq
		}
	}
}

// nextLevelUp returns the largest configured prefix length shorter than bits,
// or -1 when bits is already the least specific level.
func nextLevelUp(levels []int, bits int) int {
	next := -1
	for _, l := range levels {
		if l < bits && l > next {
			next = l
		}
	}
	return next
}

// Clear resets the counter.
func (c *HHHCounter) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = make(map[netip.Prefix]int)
	c.total = 0
}
