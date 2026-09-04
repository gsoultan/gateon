// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mitigation

import (
	"net/netip"
	"sync/atomic"
)

// GATEON_MITIGATION_ALLOWLIST is documented as a "CIDR/IP list never mitigated",
// and until this file existed exactly one thing honoured it: the Responder,
// which handles correlated incidents after the fact.
//
// Every synchronous way gateon mitigates ignored it. An operator who allowlisted
// their office egress, their monitoring vendor or their own security team's
// scanner was still refused by the reputation blocker, still banned for hours by
// the honeypot, still delayed by the tarpit and still challenged by
// proof-of-work. The setting did not do the one thing its name promises, and the
// failure was silent in the worst direction: it looks like it worked right up
// until the moment someone is locked out.
//
// So the allowlist moves here, where every enforcement site can reach it, and
// the Responder becomes one caller among several rather than the only one.

// allowlist holds the configured prefixes. An atomic pointer because it is read
// on the request path by several middlewares and written once at startup and on
// config reload — a mutex here would be a lock on every request for a value that
// changes approximately never.
var allowlist atomic.Pointer[[]netip.Prefix]

// SetAllowlist installs the prefixes that must never be actively mitigated.
//
// Passing nil or an empty slice clears it, which is the default: an install that
// has configured nothing pays a single nil check per enforcement site.
func SetAllowlist(prefixes []netip.Prefix) {
	if len(prefixes) == 0 {
		allowlist.Store(nil)
		return
	}
	cp := make([]netip.Prefix, len(prefixes))
	copy(cp, prefixes)
	allowlist.Store(&cp)
}

// IsAllowlisted reports whether this address is exempt from active mitigation.
//
// It exempts *enforcement*, never *observation*. An allowlisted source still has
// its threats recorded, still appears in the dashboard and still feeds
// correlation — an operator who allowlists their own pentest team wants to see
// exactly what it found, and a control that hid the evidence along with the
// block would be worse than no allowlist at all.
//
// Written to be cheap enough for the request path: the common case is an empty
// list and one atomic load, and a configured list is a handful of prefix
// comparisons over values that never allocate.
func IsAllowlisted(ip string) bool {
	// Deliberately tiny so the compiler inlines it. This sits on the request
	// path -- the reputation blocker carrying it runs on every route -- and the
	// overwhelmingly common case is an install that has configured nothing, which
	// should cost one atomic load and a nil check. Folding the parse and the scan
	// in here made the whole function too large to inline and cost ~24ns per
	// request for a branch that is almost never taken.
	p := allowlist.Load()
	if p == nil {
		return false
	}
	return allowlistContains(*p, ip)
}

// allowlistContains is the slow path, reached only when prefixes are configured.
func allowlistContains(prefixes []netip.Prefix, ip string) bool {
	if ip == "" || len(prefixes) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		// An address that will not parse cannot be shown to be allowlisted, and
		// the safe direction for a security exemption is to withhold it.
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// AllowlistSize reports how many prefixes are configured, for startup logging so
// an operator can see the setting was read.
func AllowlistSize() int {
	if p := allowlist.Load(); p != nil {
		return len(*p)
	}
	return 0
}
