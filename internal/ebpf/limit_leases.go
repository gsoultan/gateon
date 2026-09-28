// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
)

// AdaptiveLimitLease is how long an adaptive rate limit stays in the kernel
// after it was last set.
//
// Five paths install these limits -- the WAF, the HTTP rate limiter, anomaly
// detection, the diagnostics loop's automatic mitigation and the RL limiter --
// into a kernel hash map that has no expiry, and only the RL limiter ever
// removed one, and only its own. Every other limit lasted as long as the eBPF
// manager: one WAF hit from a shared address throttled everyone behind it to a
// packet a second until the process restarted or eBPF was reconfigured, and a
// full map refused every new limit. Each writer sets its limit again for as
// long as its reason persists, so a lease a few times the slowest of them (the
// one-minute analysis loop) releases an address minutes after it stops.
const AdaptiveLimitLease = 5 * time.Minute

// AdaptiveLimit is one adaptive rate limit in the kernel, as the operator is
// shown it.
type AdaptiveLimit struct {
	Key      string        // the address; for IPv6 the network address of its /64
	Interval time.Duration // the spacing enforced between the source's packets
	Reason   string        // why it was set; empty when the writer did not say
	SetAt    time.Time     // when it was last set or renewed
	Expires  time.Time     // when it lapses unless it is set again
}

// maxLimitReasonBytes bounds a recorded reason. Reasons are written by code,
// not clients, but the table can hold twenty thousand of them.
const maxLimitReasonBytes = 200

// limitLeases records each adaptive limit in force, keyed as the kernel keys
// it: a lease is only taken after the kernel accepted the limit, so the table
// is bounded by the kernel maps' capacity (10240 IPv4 addresses and 10240 IPv6
// /64s), including for IPv6, where a whole /64 shares one entry however many
// addresses an attacker rotates through.
type limitLeases struct {
	mu      sync.Mutex
	entries map[string]AdaptiveLimit
}

// renew records limit as the one in force for its key.
func (l *limitLeases) renew(limit AdaptiveLimit) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[string]AdaptiveLimit)
	}
	l.entries[limit.Key] = limit
}

// drop forgets key's lease.
func (l *limitLeases) drop(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// reset forgets every lease: a freshly swapped-in manager starts with empty
// maps, so there is nothing left to release.
func (l *limitLeases) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.entries)
}

// takeExpired removes and returns every lease that ended by now.
func (l *limitLeases) takeExpired(now time.Time) []AdaptiveLimit {
	l.mu.Lock()
	defer l.mu.Unlock()
	var expired []AdaptiveLimit
	for key, limit := range l.entries {
		if !limit.Expires.After(now) {
			expired = append(expired, limit)
			delete(l.entries, key)
		}
	}
	return expired
}

// snapshot copies the table, most recently set first.
func (l *limitLeases) snapshot() []AdaptiveLimit {
	l.mu.Lock()
	out := make([]AdaptiveLimit, 0, len(l.entries))
	for _, limit := range l.entries {
		out = append(out, limit)
	}
	l.mu.Unlock()
	slices.SortFunc(out, func(a, b AdaptiveLimit) int {
		if c := b.SetAt.Compare(a.SetAt); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out
}

// count is how many leases are in force.
func (l *limitLeases) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// LimitKey names the kernel entry an adaptive limit for s lands in: the
// address for IPv4, the /64 for IPv6, spelled as that network's address so that
// ClearAdaptiveRateLimit on it removes the same entry. Anything that keeps
// state per limit keys it this way, or an attacker walking a /64 is a new
// entry per address to it and one entry to the kernel.
func LimitKey(s string) (string, bool) {
	return leaseKey(s)
}

// leaseKey is LimitKey.
func leaseKey(s string) (string, bool) {
	ip, is4, err := parseAddress(s)
	if err != nil {
		return "", false
	}
	if is4 {
		return ip.String(), true
	}
	return ip.Mask(net.CIDRMask(64, 128)).String(), true
}

// ExpireLeases releases the adaptive limits and the shuns whose lease has run
// out, checking every interval until ctx ends.
func (h *Holder) ExpireLeases(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			h.expireAdaptiveLimits(now)
			h.expireShuns(now)
		}
	}
}

// shunLeases records each shun the Holder put in the kernel, keyed as the
// kernel keys it (leaseKey), with when it lapses: the zero time for a shun
// that holds until released. Bounded like limitLeases, by the kernel maps.
type shunLeases struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// hold records until as the end of key's shun. One key can carry several
// shuns -- two addresses in one IPv6 /64 -- so a shun with no end outlasts any
// lease, and of two leases the later end is kept: the sweep never lifts an
// entry something still holds.
func (l *shunLeases) hold(key string, until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = make(map[string]time.Time)
	}
	cur, ok := l.entries[key]
	if !ok || (!cur.IsZero() && (until.IsZero() || until.After(cur))) {
		l.entries[key] = until
	}
}

// drop forgets key's shun.
func (l *shunLeases) drop(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// reset forgets every shun: a swapped-in manager starts with empty maps.
func (l *shunLeases) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.entries)
}

// takeExpired removes and returns the keys whose lease ended by now.
func (l *shunLeases) takeExpired(now time.Time) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var expired []string
	for key, until := range l.entries {
		if !until.IsZero() && !until.After(now) {
			expired = append(expired, key)
			delete(l.entries, key)
		}
	}
	return expired
}

// expireShuns lifts every shun whose lease ended by now. One the kernel no
// longer holds is done; any other failure is retried on the next pass, since
// a forgotten lease is a shun nothing will ever lift.
func (h *Holder) expireShuns(now time.Time) {
	m := h.Current()
	if m == nil {
		return
	}
	for _, key := range h.shuns.takeExpired(now) {
		if err := m.UnshunIP(key); err != nil && !errors.Is(err, cebpf.ErrKeyNotExist) {
			logger.L.LogWarn("failed to lift a lapsed shun from the kernel; will retry", "ip", key, "error", err)
			h.shuns.hold(key, now)
		}
	}
}

// ShunLeaseCount is how many shuns the Holder has in the kernel.
func (h *Holder) ShunLeaseCount() int {
	h.shuns.mu.Lock()
	defer h.shuns.mu.Unlock()
	return len(h.shuns.entries)
}

// expireAdaptiveLimits releases every limit whose lease ended by now. A
// release that fails is retried on the next pass rather than forgotten, since
// a forgotten lease is exactly a limit nothing will ever lift.
func (h *Holder) expireAdaptiveLimits(now time.Time) {
	m := h.Current()
	if m == nil {
		return
	}
	for _, limit := range h.leases.takeExpired(now) {
		if err := m.ClearAdaptiveRateLimit(limit.Key); err != nil {
			logger.L.LogWarn("failed to release an expired adaptive rate limit; will retry", "ip", limit.Key, "error", err)
			h.leases.renew(limit)
		}
	}
}

// AdaptiveLimits is every adaptive limit the Holder has in force, most
// recently set first: what the dashboard lists as kernel throttles. Five
// components set them and none of them was shown anywhere, so an address could
// be held to a few packets a second with nothing on the mitigation page to say
// so or to release it from.
func (h *Holder) AdaptiveLimits() []AdaptiveLimit {
	return h.leases.snapshot()
}

// AdaptiveLimitCount is how many adaptive limits are in force, without copying
// the table.
func (h *Holder) AdaptiveLimitCount() int {
	return h.leases.count()
}

// ReasonedLimiter is a Manager that records why each adaptive limit was set.
// The Holder is one.
type ReasonedLimiter interface {
	SetAdaptiveRateLimitFor(ip string, interval time.Duration, reason string) error
}

// SetAdaptiveRateLimitFor sets an adaptive limit through m, recording reason
// where m keeps one (the Holder does); elsewhere it is SetAdaptiveRateLimit.
func SetAdaptiveRateLimitFor(m Manager, ip string, interval time.Duration, reason string) error {
	if r, ok := m.(ReasonedLimiter); ok {
		return r.SetAdaptiveRateLimitFor(ip, interval, reason)
	}
	return m.SetAdaptiveRateLimit(ip, interval)
}
