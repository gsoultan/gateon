// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"context"
	"net"
	"sync"
	"time"

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

// limitLeases records when each adaptive limit lapses, keyed as the kernel
// keys it: a lease is only taken after the kernel accepted the limit, so the
// set is bounded by the kernel maps' capacity, including for IPv6, where a
// whole /64 shares one entry however many addresses an attacker rotates
// through.
type limitLeases struct {
	mu     sync.Mutex
	expiry map[string]time.Time
}

// renew extends key's lease to until.
func (l *limitLeases) renew(key string, until time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.expiry == nil {
		l.expiry = make(map[string]time.Time)
	}
	l.expiry[key] = until
}

// drop forgets key's lease.
func (l *limitLeases) drop(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.expiry, key)
}

// reset forgets every lease: a freshly swapped-in manager starts with empty
// maps, so there is nothing left to release.
func (l *limitLeases) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.expiry)
}

// takeExpired removes and returns every key whose lease ended by now.
func (l *limitLeases) takeExpired(now time.Time) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var keys []string
	for key, until := range l.expiry {
		if !until.After(now) {
			keys = append(keys, key)
			delete(l.expiry, key)
		}
	}
	return keys
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

// ExpireAdaptiveLimits releases adaptive limits whose lease has run out,
// checking every interval until ctx ends.
func (h *Holder) ExpireAdaptiveLimits(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.expireAdaptiveLimits(time.Now())
		}
	}
}

// expireAdaptiveLimits releases every limit whose lease ended by now. A
// release that fails is retried on the next pass rather than forgotten, since
// a forgotten lease is exactly a limit nothing will ever lift.
func (h *Holder) expireAdaptiveLimits(now time.Time) {
	m := h.Current()
	if m == nil {
		return
	}
	for _, key := range h.leases.takeExpired(now) {
		if err := m.ClearAdaptiveRateLimit(key); err != nil {
			logger.L.LogWarn("failed to release an expired adaptive rate limit; will retry", "ip", key, "error", err)
			h.leases.renew(key, now)
		}
	}
}
