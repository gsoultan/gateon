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

	// rlFeedback is the reinforcement-learning feedback handler, kept here so
	// every manager swapped in receives it, not only the one present when it
	// was installed.
	rlFeedback atomic.Pointer[func(ip string, score float64)]
}

type managerContainer struct {
	m Manager
}

// NewHolder returns a Holder seeded with the (optional) initial manager. Pass
// nil to start with the eBPF subsystem disabled.
func NewHolder(initial Manager) *Holder {
	h := &Holder{}
	h.Swap(initial)
	return h
}

// Swap atomically installs m as the active underlying manager. Passing nil
// disables delegation so all subsequent calls become no-ops.
//
// m receives the feedback handler before it becomes visible, and again if a
// different one was installed while it was being swapped in, so no ordering
// of Swap and SetRLFeedbackHandler leaves the active manager without it.
func (h *Holder) Swap(m Manager) {
	before := h.rlFeedback.Load()
	if m != nil && before != nil {
		m.SetRLFeedbackHandler(*before)
	}
	h.current.Store(&managerContainer{m: m})
	if after := h.rlFeedback.Load(); m != nil && after != nil && after != before {
		m.SetRLFeedbackHandler(*after)
	}
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

// SetAdaptiveRateLimit delegates to the active manager, if any.
func (h *Holder) SetAdaptiveRateLimit(ip string, interval time.Duration) error {
	if m := h.Current(); m != nil {
		return m.SetAdaptiveRateLimit(ip, interval)
	}
	return nil
}

// ClearAdaptiveRateLimit delegates to the active manager, if any.
func (h *Holder) ClearAdaptiveRateLimit(ip string) error {
	if m := h.Current(); m != nil {
		return m.ClearAdaptiveRateLimit(ip)
	}
	return nil
}

// ApplyRLFeedback delegates to the active manager, if any.
func (h *Holder) ApplyRLFeedback(ip string, score float64) error {
	if m := h.Current(); m != nil {
		return m.ApplyRLFeedback(ip, score)
	}
	return nil
}

// SetRLFeedbackHandler installs f on the active manager and on every manager
// swapped in after it.
//
// It used to reach only the active manager. The server installs the handler
// once at startup and the security supervisor builds a new manager on every
// eBPF settings change, so the first change -- or turning eBPF on after boot
// -- silently disconnected the closed loop until the process restarted.
func (h *Holder) SetRLFeedbackHandler(f func(ip string, score float64)) {
	h.rlFeedback.Store(&f)
	if m := h.Current(); m != nil {
		m.SetRLFeedbackHandler(f)
	}
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
