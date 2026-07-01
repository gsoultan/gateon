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
	current atomic.Pointer[Manager]
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
	if m == nil {
		h.current.Store(nil)
		return
	}
	h.current.Store(&m)
}

// Current returns the active underlying manager, or nil when none is installed.
func (h *Holder) Current() Manager {
	if p := h.current.Load(); p != nil {
		return *p
	}
	return nil
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

// ShunJA3 delegates to the active manager, if any.
func (h *Holder) ShunJA3(ja3Md5 [16]byte) error {
	if m := h.Current(); m != nil {
		return m.ShunJA3(ja3Md5)
	}
	return nil
}

// UnshunJA3 delegates to the active manager, if any.
func (h *Holder) UnshunJA3(ja3Md5 [16]byte) error {
	if m := h.Current(); m != nil {
		return m.UnshunJA3(ja3Md5)
	}
	return nil
}

// ShunJA4 delegates to the active manager, if any.
func (h *Holder) ShunJA4(ja4Fingerprint string) error {
	if m := h.Current(); m != nil {
		return m.ShunJA4(ja4Fingerprint)
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
