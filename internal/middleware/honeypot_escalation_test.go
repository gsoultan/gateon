// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"testing"
	"time"
)

// The honeypot bans an address that reaches a trap path. It used to ban for a
// flat 24 hours on the first hit.
//
// The trap paths are chosen so that no legitimate client requests them — /.env,
// /.git, /.aws — which makes one hit strong evidence about the *request*. But the
// ban lands on an address, and addresses are shared. Behind CGNAT or a corporate
// egress, a security scan the customer ran themselves, one compromised laptop or
// one over-eager crawler took the entire office off the site until the next day,
// and nothing in the product explained why.
//
// Root cause in one sentence: the confidence the trap earns is about the request,
// and it was being spent on an identity that belongs to many people.
//
// Repetition over time is the corroboration a single request cannot supply, so
// the ban escalates instead of starting at its maximum — the same principle
// internal/security/mitigation already applies to correlated incidents.

// resetHoneypotState clears the package-level ban and strike maps.
//
// These are process-global, so a test that did not reset them would inherit
// strikes from whichever test ran first and assert against a ladder position it
// did not set up.
func resetHoneypotState(t *testing.T) {
	t.Helper()
	blocklistMu.Lock()
	clear(honeypotBlocklist)
	clear(honeypotStrikes)
	blocklistMu.Unlock()
	t.Cleanup(func() {
		blocklistMu.Lock()
		clear(honeypotBlocklist)
		clear(honeypotStrikes)
		blocklistMu.Unlock()
	})
}

// TestHoneypotBanEscalatesRatherThanStartingAtADay is the regression test.
//
// The first hit must be cheap enough that a mistake is survivable, and repeated
// hits must reach the full day — an attacker who keeps probing should not get a
// discount for having been caught before.
func TestHoneypotBanEscalatesRatherThanStartingAtADay(t *testing.T) {
	resetHoneypotState(t)

	const ip = "203.0.113.40"
	now := time.Now()

	want := []time.Duration{
		15 * time.Minute,
		1 * time.Hour,
		6 * time.Hour,
		24 * time.Hour,
		24 * time.Hour, // and stays there
		24 * time.Hour,
	}

	for i, w := range want {
		got := honeypotBanFor(ip, now)
		if got != w {
			t.Errorf("hit %d banned for %s, want %s.\n"+
				"A first hit costing a full day is what takes a shared egress offline "+
				"for something one machine behind it did.", i+1, got, w)
		}
	}
}

// TestHoneypotStrikesExpire keeps a dynamic address from inheriting a record.
//
// Addresses are reassigned. A client that stays away past the strike window is a
// different party as far as the gateway can tell, and starting them mid-ladder
// would punish them for a stranger's behaviour.
func TestHoneypotStrikesExpire(t *testing.T) {
	resetHoneypotState(t)

	const ip = "203.0.113.41"
	now := time.Now()

	if got := honeypotBanFor(ip, now); got != 15*time.Minute {
		t.Fatalf("first hit banned for %s, want 15m", got)
	}
	if got := honeypotBanFor(ip, now); got != time.Hour {
		t.Fatalf("second hit banned for %s, want 1h", got)
	}

	// Return after the window has passed.
	later := now.Add(honeypotStrikeWindow + time.Minute)
	if got := honeypotBanFor(ip, later); got != 15*time.Minute {
		t.Errorf("after %s away the address was banned for %s, want 15m — an "+
			"expired record must not carry over to whoever holds the address now",
			honeypotStrikeWindow, got)
	}
}

// TestHoneypotStrikesAreIndependentPerAddress guards the obvious way to get this
// wrong: a shared counter that escalates for everyone at once.
func TestHoneypotStrikesAreIndependentPerAddress(t *testing.T) {
	resetHoneypotState(t)

	now := time.Now()
	const persistent = "203.0.113.42"
	const firstTimer = "198.51.100.9"

	for range 4 {
		honeypotBanFor(persistent, now)
	}

	if got := honeypotBanFor(firstTimer, now); got != 15*time.Minute {
		t.Errorf("an address on its first hit was banned for %s, want 15m — "+
			"escalation leaked from another client", got)
	}
}

// TestHoneypotBanIsBoundedUnderAScan pins the memory ceiling.
//
// The strike map is keyed by attacker-supplied addresses, so it needs the same
// bound the blocklist has. At the cap it must refuse to grow rather than track
// every source of a distributed scan forever.
func TestHoneypotBanIsBoundedUnderAScan(t *testing.T) {
	resetHoneypotState(t)

	now := time.Now()
	for i := range maxHoneypotBlocklist + 500 {
		honeypotBanFor(netAddrForIndex(i), now)
	}

	blocklistMu.RLock()
	size := len(honeypotStrikes)
	blocklistMu.RUnlock()

	if size > maxHoneypotBlocklist {
		t.Errorf("strike map grew to %d entries, cap is %d — a map keyed by "+
			"attacker-chosen addresses with no ceiling is a memory exhaustion "+
			"primitive", size, maxHoneypotBlocklist)
	}
}

// netAddrForIndex builds a distinct IPv4 address per index.
func netAddrForIndex(i int) string {
	return "10." + itoa((i>>16)&0xff) + "." + itoa((i>>8)&0xff) + "." + itoa(i&0xff)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [3]byte
	n := len(b)
	for v > 0 {
		n--
		b[n] = byte('0' + v%10)
		v /= 10
	}
	return string(b[n:])
}
