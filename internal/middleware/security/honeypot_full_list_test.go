// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"fmt"
	"testing"
	"time"
)

// TestAFullBanListStillBansTheNextScanner: at the cap the ban list refused to
// grow, so once it was full the next scanner to trip a trap -- from anywhere --
// was not banned at all. Keying IPv6 bans on the /64 stopped one /64 from
// filling it, but a /48, which is normally one customer, holds 65,536 of them:
// the same customer could still switch the honeypot off for everyone. A full
// list must make room, not stop banning.
func TestAFullBanListStillBansTheNextScanner(t *testing.T) {
	blocklistMu.Lock()
	original := honeypotBlocklist
	honeypotBlocklist = make(map[string]time.Time, maxHoneypotBlocklist)
	blocklistMu.Unlock()
	t.Cleanup(func() {
		blocklistMu.Lock()
		honeypotBlocklist = original
		blocklistMu.Unlock()
	})

	// One customer's /48, one trap hit per /64, every ban still in force.
	for i := range maxHoneypotBlocklist {
		if _, banned := blockHoneypotIP(fmt.Sprintf("2001:db8:1:%x::1", i), time.Now().Add(24*time.Hour)); !banned {
			t.Fatalf("precondition: ban %d of %d was not recorded", i+1, maxHoneypotBlocklist)
		}
	}

	key, banned := blockHoneypotIP("198.51.100.23", time.Now().Add(15*time.Minute))
	if !banned {
		t.Fatalf("with the ban list full, a new scanner (%s) was not banned", key)
	}
	if !honeypotBanActive("198.51.100.23") {
		t.Error("the new ban was reported recorded but the address is not refused")
	}
	blocklistMu.RLock()
	size := len(honeypotBlocklist)
	blocklistMu.RUnlock()
	if size > maxHoneypotBlocklist {
		t.Errorf("making room grew the ban list to %d entries, over its cap of %d", size, maxHoneypotBlocklist)
	}
}

// TestEvictionDropsTheBanClosestToLapsing: of the bans it compares, eviction
// drops the one that would have ended soonest anyway, not a fresh one. With
// fewer bans than the sample, every ban is compared.
func TestEvictionDropsTheBanClosestToLapsing(t *testing.T) {
	blocklistMu.Lock()
	original := honeypotBlocklist
	now := time.Now()
	honeypotBlocklist = map[string]time.Time{
		"192.0.2.1": now.Add(6 * time.Hour),
		"192.0.2.2": now.Add(15 * time.Minute),
		"192.0.2.3": now.Add(24 * time.Hour),
		"192.0.2.4": now.Add(time.Hour),
	}
	evictSoonestExpiringBan()
	_, stillThere := honeypotBlocklist["192.0.2.2"]
	left := len(honeypotBlocklist)
	honeypotBlocklist = original
	blocklistMu.Unlock()

	if stillThere || left != 3 {
		t.Errorf("after one eviction: %d bans left, the 15-minute ban still there = %v; want 3 left and it gone", left, stillThere)
	}
}
