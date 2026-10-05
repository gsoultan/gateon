// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"
)

// randomFeed is n random host entries, IPv4 across the whole space or IPv6
// across 2000::/3: the spread a real blocklist has, and the worst case for an
// index that shares structure between neighbours.
func randomFeed(n int, v6 bool) string {
	rng := rand.New(rand.NewPCG(7, 11))
	var b strings.Builder
	for range n {
		if v6 {
			var a [16]byte
			for i := range a {
				a[i] = byte(rng.IntN(256))
			}
			a[0] = 0x20 | a[0]&0x1f
			b.WriteString(netip.AddrFrom16(a).String())
		} else {
			fmt.Fprintf(&b, "%d.%d.%d.%d", 1+rng.IntN(223), rng.IntN(256), rng.IntN(256), rng.IntN(256))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// heapObjects is the live and not-yet-swept heap, in bytes.
func heapObjects() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}

// peakDuring samples the heap every millisecond while fn runs and returns
// the highest reading.
func peakDuring(fn func()) uint64 {
	var peak uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Millisecond)
		defer t.Stop()
		for {
			peak = max(peak, heapObjects())
			select {
			case <-done:
				return
			case <-t.C:
			}
		}
	}()
	fn()
	close(done)
	wg.Wait()
	return max(peak, heapObjects())
}

// BenchmarkFeedLookup is the per-request cost of asking a loaded feed about a
// client it does not list (the path nearly every request takes) and one it
// does, at 4096 and a million random IPv4 entries.
func BenchmarkFeedLookup(b *testing.B) {
	for _, n := range []int{4096, 1_000_000} {
		s := quietStore(serveFeed(b, randomFeed(n, false)))
		s.update(context.Background())
		listed := strings.SplitN(randomFeed(1, false), "\n", 2)[0]
		for _, ip := range []struct{ name, addr string }{{"miss", "203.0.113.42"}, {"hit", listed}} {
			b.Run(fmt.Sprintf("%d-%s", n, ip.name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					s.Listed(ip.addr)
				}
			})
		}
	}
}

// BenchmarkFeedMemory is DP-N2's measurement: the heap a loaded feed holds,
// and the heap a refresh of it peaks at and allocates, for a million IPv4
// entries and for IPv6. Run with -benchtime 1x; the numbers are reported as
// metrics, not as time.
func BenchmarkFeedMemory(b *testing.B) {
	for _, tc := range []struct {
		name string
		n    int
		v6   bool
	}{{"ipv4-1M", 1_000_000, false}, {"ipv6-250k", 250_000, true}, {"ipv6-1M", 1_000_000, true}} {
		b.Run(tc.name, func(b *testing.B) {
			url := serveFeed(b, randomFeed(tc.n, tc.v6))
			for range b.N {
				runtime.GC()
				base := heapObjects()
				s := quietStore(url)
				s.update(context.Background())
				runtime.GC()
				held := heapObjects() - base
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				peak := peakDuring(func() { s.update(context.Background()) })
				var after runtime.MemStats
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(held)/(1<<20), "held-MiB")
				b.ReportMetric(float64(peak-base)/(1<<20), "refresh-peak-MiB")
				b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/(1<<20), "refresh-alloc-MiB")
				runtime.KeepAlive(s)
			}
		})
	}
}
