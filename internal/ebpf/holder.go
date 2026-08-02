// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

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
func (h *Holder) Swap(m Manager) {
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

// BlockCountry delegates to the active manager, if any.
func (h *Holder) BlockCountry(countryCode string) error {
	if m := h.Current(); m != nil {
		return m.BlockCountry(countryCode)
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

// ApplyRLFeedback delegates to the active manager, if any.
func (h *Holder) ApplyRLFeedback(ip string, score float64) error {
	if m := h.Current(); m != nil {
		return m.ApplyRLFeedback(ip, score)
	}
	return nil
}

// SetRLFeedbackHandler delegates to the active manager, if any.
func (h *Holder) SetRLFeedbackHandler(f func(ip string, score float64)) {
	if m := h.Current(); m != nil {
		m.SetRLFeedbackHandler(f)
	}
}

// ShunJA4 delegates to the active manager, if any.
func (h *Holder) ShunJA4(ja4Fingerprint string) error {
	if m := h.Current(); m != nil {
		return m.ShunJA4(ja4Fingerprint)
	}
	return nil
}

// UnshunJA4 delegates to the active manager, if any.
func (h *Holder) UnshunJA4(ja4Fingerprint string) error {
	if m := h.Current(); m != nil {
		return m.UnshunJA4(ja4Fingerprint)
	}
	return nil
}

// BlocklistCuckoo delegates to the active manager, if any.
func (h *Holder) BlocklistCuckoo(ip string) error {
	if m := h.Current(); m != nil {
		return m.BlocklistCuckoo(ip)
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
