// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
)

// recordingLimiter is an eBPF manager that records the adaptive limits it is
// asked to install and does nothing else. It keys them as the kernel does
// (kernelKey), so a limit set on one IPv6 address and cleared by its /64 is
// gone, as it would be.
type recordingLimiter struct {
	mu      sync.Mutex
	limits  map[string]time.Duration
	cleared map[string]int
}

func (r *recordingLimiter) SetAdaptiveRateLimit(ip string, d time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.limits == nil {
		r.limits = map[string]time.Duration{}
	}
	r.limits[kernelKey(ip)] = d
	return nil
}

func (r *recordingLimiter) ClearAdaptiveRateLimit(ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleared == nil {
		r.cleared = map[string]int{}
	}
	r.cleared[ip]++
	delete(r.limits, kernelKey(ip))
	return nil
}

func (r *recordingLimiter) throttled(ips []string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, ip := range ips {
		if _, ok := r.limits[kernelKey(ip)]; ok {
			n++
		}
	}
	return n
}

// kernelKey is the entry the kernel keeps a limit for ip under: the address,
// or its /64 for IPv6.
func kernelKey(ip string) string {
	if key, ok := ebpf.LimitKey(ip); ok {
		return key
	}
	return ip
}

func (r *recordingLimiter) Start(context.Context)                     {}
func (r *recordingLimiter) ShunIP(string) error                       { return nil }
func (r *recordingLimiter) UnshunIP(string) error                     { return nil }
func (r *recordingLimiter) UpdateManagementWhitelist([]string) error  { return nil }
func (r *recordingLimiter) SetPortKnockingSequence([]int32) error     { return nil }
func (r *recordingLimiter) UpdateLoadBalancerBackends([]string) error { return nil }
func (r *recordingLimiter) RegisterPhantomPort(uint32) error          { return nil }
func (r *recordingLimiter) UnregisterPhantomPort(uint32) error        { return nil }
func (r *recordingLimiter) GetTopIPs(int) ([]ebpf.IPStat, error)      { return nil, nil }
func (r *recordingLimiter) GetMapStats() (ebpf.MapStats, error)       { return ebpf.MapStats{}, nil }

// limitedAddresses is every address with a limit in force, sorted.
func (r *recordingLimiter) limitedAddresses() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Sorted(maps.Keys(r.limits))
}
