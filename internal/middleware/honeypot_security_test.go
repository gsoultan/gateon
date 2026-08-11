// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"testing"
	"time"
)

// The honeypot bans a client IP for 24 hours on a single request to a trap
// path. That is a reasonable response to a path nobody legitimate would ever
// request — and a denial of service against your own users for any path they
// would.
//
// Found by running the OWASP CRS regression corpus against a live gateway:
// test 942200 requests /wp-admin/load-scripts.php, a perfectly ordinary
// WordPress URL, and every subsequent request from that address — benign
// included — was refused. The gateway had effectively banned the test runner.

// TestHoneypotDefaults_ExcludeLegitimateApplicationPaths guards the default
// trap list against paths real users visit.
//
// /wp-admin and /admin are not attacker-only markers: they are the front door
// of WordPress and of most admin panels. Trapping them bans the first
// administrator who logs in, and behind CGNAT or a corporate egress it bans
// everyone sharing that address for a day. A default must be safe for the
// people running the software, not only hostile to scanners.
func TestHoneypotDefaults_ExcludeLegitimateApplicationPaths(t *testing.T) {
	// Paths that belong to real applications and must never be trapped by
	// default. An operator may still opt in explicitly via
	// SecurityAdvanced.Deception.HoneypotPaths.
	legitimate := []string{"/admin", "/wp-admin"}

	for _, p := range legitimate {
		t.Run(p, func(t *testing.T) {
			for _, def := range defaultHoneypotPaths() {
				if def == p {
					t.Errorf("default honeypot traps %q, a path real users request.\n"+
						"First legitimate visit bans that IP for 24h; behind a shared egress "+
						"it bans every user behind it.\n"+
						"Fix: keep only unambiguous attacker markers in the default list and "+
						"require opt-in for application paths.", p)
				}
			}
		})
	}
}

// TestHoneypotDefaults_KeepUnambiguousTraps is the other half of the contract:
// trimming the defaults must not empty them. These paths have no legitimate
// client-side use, so trapping them costs no real user anything.
func TestHoneypotDefaults_KeepUnambiguousTraps(t *testing.T) {
	want := []string{"/.env", "/.git", "/.aws", "/.ssh"}
	got := defaultHoneypotPaths()

	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("default honeypot no longer traps %q; it has no legitimate "+
				"client use and is a high-signal scanner marker", w)
		}
	}
}

// TestHoneypotBlocklist_IsBounded pins a memory invariant.
//
// honeypotBlocklist is a package-level map keyed by client IP, and entries are
// only removed lazily when that same IP comes back after expiry. An address
// that trips a trap once and never returns is retained forever, so a scanner
// sweeping from many source addresses grows the map without bound. Anything
// keyed by attacker-controlled data needs a ceiling.
func TestHoneypotBlocklist_IsBounded(t *testing.T) {
	blocklistMu.Lock()
	original := honeypotBlocklist
	honeypotBlocklist = make(map[string]time.Time)
	blocklistMu.Unlock()

	t.Cleanup(func() {
		blocklistMu.Lock()
		honeypotBlocklist = original
		blocklistMu.Unlock()
	})

	// Simulate a distributed scan: many source addresses, each tripping a trap
	// once and never returning. This must go through the same entry point the
	// middleware uses, so the test exercises the real bound.
	const sources = 50_000
	for i := range sources {
		blockHoneypotIP(ipv4For(i), time.Now().Add(24*time.Hour))
	}

	blocklistMu.RLock()
	size := len(honeypotBlocklist)
	blocklistMu.RUnlock()

	if size >= sources {
		t.Errorf("honeypot blocklist grew to %d entries with no eviction.\n"+
			"It is keyed by client IP with only lazy per-IP cleanup, so a scan from "+
			"many addresses retains every one of them indefinitely.\n"+
			"Fix: cap the map (LRU) or run a periodic sweep of expired entries.", size)
	}
}

// ipv4For turns a counter into a distinct dotted-quad, so the test exercises
// distinct map keys without depending on any address being routable.
func ipv4For(i int) string {
	const digits = "0123456789"
	itoa := func(n int) string {
		if n == 0 {
			return "0"
		}
		var b [3]byte
		p := len(b)
		for n > 0 {
			p--
			b[p] = digits[n%10]
			n /= 10
		}
		return string(b[p:])
	}
	return "10." + itoa((i>>16)&0xFF) + "." + itoa((i>>8)&0xFF) + "." + itoa(i&0xFF)
}
