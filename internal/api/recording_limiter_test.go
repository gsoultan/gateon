// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
)

// recordingLimiter is an eBPF manager that records the adaptive limits it is
// asked to install and does nothing else.
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
	r.limits[ip] = d
	return nil
}

func (r *recordingLimiter) ClearAdaptiveRateLimit(ip string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleared == nil {
		r.cleared = map[string]int{}
	}
	r.cleared[ip]++
	return nil
}

func (r *recordingLimiter) throttled(ips []string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, ip := range ips {
		if _, ok := r.limits[ip]; ok {
			n++
		}
	}
	return n
}

func (r *recordingLimiter) Start(context.Context)                      {}
func (r *recordingLimiter) ShunIP(string) error                        { return nil }
func (r *recordingLimiter) UnshunIP(string) error                      { return nil }
func (r *recordingLimiter) UpdateManagementWhitelist([]string) error   { return nil }
func (r *recordingLimiter) SetPortKnockingSequence([]int32) error      { return nil }
func (r *recordingLimiter) UpdateLoadBalancerBackends([]string) error  { return nil }
func (r *recordingLimiter) ApplyRLFeedback(string, float64) error      { return nil }
func (r *recordingLimiter) SetRLFeedbackHandler(func(string, float64)) {}
func (r *recordingLimiter) RegisterPhantomPort(uint32) error           { return nil }
func (r *recordingLimiter) UnregisterPhantomPort(uint32) error         { return nil }
func (r *recordingLimiter) GetTopIPs(int) ([]ebpf.IPStat, error)       { return nil, nil }
func (r *recordingLimiter) GetMapStats() (ebpf.MapStats, error)        { return ebpf.MapStats{}, nil }
