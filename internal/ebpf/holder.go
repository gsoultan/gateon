// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"context"
	"sync/atomic"
	"time"
)

var (
	// GlobalHolder is the system-wide eBPF manager instance.
	GlobalHolder = NewHolder(nil)
)

// Holder is a thread-safe Manager that delegates every call to a swappable
// underlying Manager. It lets the security supervisor hot-reload the eBPF
// subsystem at runtime without invalidating the Manager reference captured by
// the request path (middleware factory / proxy cache), the alerting subsystem,
// or the metrics poll loop.
//
// When no underlying manager is installed (eBPF disabled), every mutating call
// is a safe no-op and GetMapStats returns empty stats, mirroring the behaviour
// of a disabled eBPF subsystem.
type Holder struct {
	current atomic.Value // holds *managerContainer

	// leases is when each adaptive rate limit set through the Holder lapses;
	// see AdaptiveLimitLease.
	leases limitLeases
	now    func() time.Time // injectable for tests
}

type managerContainer struct {
	m Manager
}

// NewHolder returns a Holder seeded with the (optional) initial manager. Pass
// nil to start with the eBPF subsystem disabled.
func NewHolder(initial Manager) *Holder {
	h := &Holder{now: time.Now}
	h.Swap(initial)
	return h
}

// Swap atomically installs m as the active underlying manager. Passing nil
// disables delegation so all subsequent calls become no-ops.
func (h *Holder) Swap(m Manager) {
	h.leases.reset()
	h.current.Store(&managerContainer{m: m})
}

// Current returns the active underlying manager, or nil when none is installed.
func (h *Holder) Current() Manager {
	val := h.current.Load()
	if val == nil {
		return nil
	}
	return val.(*managerContainer).m
}

// Start delegates to the active manager, if any.
func (h *Holder) Start(ctx context.Context) {
	if m := h.Current(); m != nil {
		m.Start(ctx)
	}
}

// ShunIP delegates to the active manager, if any.
func (h *Holder) ShunIP(ip string) error {
	if m := h.Current(); m != nil {
		return m.ShunIP(ip)
	}
	return nil
}

// UnshunIP delegates to the active manager, if any.
func (h *Holder) UnshunIP(ip string) error {
	if m := h.Current(); m != nil {
		return m.UnshunIP(ip)
	}
	return nil
}

// UpdateManagementWhitelist delegates to the active manager, if any.
func (h *Holder) UpdateManagementWhitelist(ips []string) error {
	if m := h.Current(); m != nil {
		return m.UpdateManagementWhitelist(ips)
	}
	return nil
}

// SetPortKnockingSequence delegates to the active manager, if any.
func (h *Holder) SetPortKnockingSequence(seq []int32) error {
	if m := h.Current(); m != nil {
		return m.SetPortKnockingSequence(seq)
	}
	return nil
}

// UpdateLoadBalancerBackends delegates to the active manager, if any.
func (h *Holder) UpdateLoadBalancerBackends(ips []string) error {
	if m := h.Current(); m != nil {
		return m.UpdateLoadBalancerBackends(ips)
	}
	return nil
}

// SetAdaptiveRateLimit delegates to the active manager, if any, and leases the
// limit for AdaptiveLimitLease: ExpireAdaptiveLimits lifts it unless it is set
// again before then. The limit is listed without a reason; writers that can
// say why use SetAdaptiveRateLimitFor.
func (h *Holder) SetAdaptiveRateLimit(ip string, interval time.Duration) error {
	return h.SetAdaptiveRateLimitFor(ip, interval, "")
}

// SetAdaptiveRateLimitFor is SetAdaptiveRateLimit, recording reason for the
// operator (AdaptiveLimits). The last writer's reason is the one listed, as
// its interval is the one the kernel enforces.
func (h *Holder) SetAdaptiveRateLimitFor(ip string, interval time.Duration, reason string) error {
	m := h.Current()
	if m == nil {
		return nil
	}
	if err := m.SetAdaptiveRateLimit(ip, interval); err != nil {
		return err
	}
	if key, ok := leaseKey(ip); ok {
		now := h.clock()
		if len(reason) > maxLimitReasonBytes {
			reason = reason[:maxLimitReasonBytes]
		}
		h.leases.renew(AdaptiveLimit{
			Key: key, Interval: interval, Reason: reason, SetAt: now, Expires: now.Add(AdaptiveLimitLease),
		})
	}
	return nil
}

// ClearAdaptiveRateLimit delegates to the active manager, if any.
func (h *Holder) ClearAdaptiveRateLimit(ip string) error {
	m := h.Current()
	if m == nil {
		return nil
	}
	if err := m.ClearAdaptiveRateLimit(ip); err != nil {
		return err
	}
	if key, ok := leaseKey(ip); ok {
		h.leases.drop(key)
	}
	return nil
}

// RegisterPhantomPort delegates to the active manager, if any.
func (h *Holder) RegisterPhantomPort(port uint32) error {
	if m := h.Current(); m != nil {
		return m.RegisterPhantomPort(port)
	}
	return nil
}

// UnregisterPhantomPort delegates to the active manager, if any.
func (h *Holder) UnregisterPhantomPort(port uint32) error {
	if m := h.Current(); m != nil {
		return m.UnregisterPhantomPort(port)
	}
	return nil
}

// GetTopIPs delegates to the active manager, if any.
func (h *Holder) GetTopIPs(limit int) ([]IPStat, error) {
	if m := h.Current(); m != nil {
		return m.GetTopIPs(limit)
	}
	return nil, nil
}

// GetMapStats delegates to the active manager, returning empty stats when the
// eBPF subsystem is disabled.
func (h *Holder) GetMapStats() (MapStats, error) {
	if m := h.Current(); m != nil {
		return m.GetMapStats()
	}
	return MapStats{}, nil
}

// clock is the Holder's time source; a zero Holder reads the wall clock.
func (h *Holder) clock() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
}
