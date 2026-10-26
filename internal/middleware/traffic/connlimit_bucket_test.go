// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"sync"
	"testing"
)

// The per-IP connection map held each address's in-flight count in a
// buffered channel, built and dropped with the bucket on every lone request.
// The count is now a plain integer under the shard lock, and buckets are
// pooled. The limit must still hold exactly at the cap, an address refused a
// slot must not stay in the map, and releasing the last slot must drop the
// address so the map is bounded by the number of addresses in flight.
func TestPerIPConnMapAcquireHoldsTheCapAndDropsIdleAddresses(t *testing.T) {
	m := newPerIPConnMap()
	const cap = 2

	for i := range cap {
		if !m.acquire("198.51.100.7", cap) {
			t.Fatalf("request %d of %d was refused a slot", i+1, cap)
		}
	}
	if m.acquire("198.51.100.7", cap) {
		t.Fatal("a third request got a slot past a cap of two")
	}
	if n := len(m.getShard("198.51.100.7").buckets); n != 1 {
		t.Fatalf("address count = %d, want 1", n)
	}

	m.release("198.51.100.7")
	if !m.acquire("198.51.100.7", cap) {
		t.Fatal("a released slot was not granted again")
	}
	m.release("198.51.100.7")
	m.release("198.51.100.7")
	if n := len(m.getShard("198.51.100.7").buckets); n != 0 {
		t.Fatalf("an address with nothing in flight is still in the map (%d entries)", n)
	}

	// An address only ever refused -- a spoofable key an attacker rotates --
	// must leave nothing behind.
	if m.acquire("203.0.113.9", 0) {
		t.Fatal("a cap of zero granted a slot")
	}
	if n := len(m.getShard("203.0.113.9").buckets); n != 0 {
		t.Fatalf("a refused address stayed in the map (%d entries)", n)
	}
	// Releasing what was never acquired is a no-op, not a negative count.
	m.release("203.0.113.9")
	if !m.acquire("203.0.113.9", 1) {
		t.Fatal("a stray release broke the next acquire")
	}
}

func TestPerIPConnMapIsSafeUnderConcurrentAcquireAndRelease(t *testing.T) {
	m := newPerIPConnMap()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 200 {
				if m.acquire("198.51.100.7", 8) {
					m.release("198.51.100.7")
				}
			}
		})
	}
	wg.Wait()
	if n := len(m.getShard("198.51.100.7").buckets); n != 0 {
		t.Fatalf("map holds %d addresses after every request ended", n)
	}
}
