// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"sync"
	"testing"
)

// rotatingAddress returns the i-th of a run of distinct IPv6 addresses. A
// client on a /64 has 2^64 of these to choose from, so "one entry per address"
// is "one entry per request" for anyone who wants it to be.
func rotatingAddress(i int) string {
	return fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff)
}

// TestAggregatorIPWindowIsBounded covers the per-IP anomaly window that every
// proxied request lands in (RecordRequest is called from the standard
// middleware chain with the client address).
//
// The window is keyed by that address and used to grow by one entry per
// distinct client, dropping an entry only once it had been idle for ten
// minutes. At a few thousand requests a second from rotating addresses that is
// hundreds of megabytes inside the prune interval, on a gateway sized for a
// 2 GB host -- the same unbounded-by-attacker-address shape that the
// bandwidth tracker in ipstats.go was bounded against, in the one sibling that
// was not.
func TestAggregatorIPWindowIsBounded(t *testing.T) {
	a := &LocalMetricsAggregator{ipStats: &sync.Map{}}
	distinct := 2 * maxAggregatorIPs
	for i := range distinct {
		a.RecordRequest(rotatingAddress(i), 200)
	}

	n := 0
	a.ipStats.Range(func(_, _ any) bool {
		n++
		return true
	})
	if n > maxAggregatorIPs {
		t.Fatalf("%d addresses tracked after %d distinct clients; the window is bounded at %d",
			n, distinct, maxAggregatorIPs)
	}
}

// TestHHHCounterIsBounded covers the hierarchical heavy-hitter table.
//
// Every recorded threat adds the attacker's address at four prefix widths, and
// a reputation shun records a threat for every request it blocks -- so a
// shunned client rotating addresses added entries until the daily reset with
// nothing in between. Once the table is full, prefixes already present keep
// counting and new ones are not opened; the wider levels an attacker's range
// falls under are the ones already there.
func TestHHHCounterIsBounded(t *testing.T) {
	c := NewHHHCounter()
	for i := range maxHHHPrefixes {
		c.Add(rotatingAddress(i)) // a fresh /128 and a fresh /64 every time
	}

	c.mu.RLock()
	n := len(c.counts)
	c.mu.RUnlock()
	if n > maxHHHPrefixes {
		t.Fatalf("%d prefixes tracked; the table is bounded at %d", n, maxHHHPrefixes)
	}
}

// TestAggregatorPruneDoesNotRaceWithRecord runs the request path against the
// five-minute prune, which read an entry's LastUpdate without the entry's lock
// while RecordRequest was writing it under that lock. The race detector is the
// assertion.
func TestAggregatorPruneDoesNotRaceWithRecord(t *testing.T) {
	a := &LocalMetricsAggregator{ipStats: &sync.Map{}}
	const ip = "203.0.113.7"
	a.RecordRequest(ip, 200)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 2000 {
			a.RecordRequest(ip, 200)
		}
	}()
	go func() {
		defer wg.Done()
		for range 2000 {
			a.pruneIPs()
		}
	}()
	wg.Wait()
}
