// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/time/rate"
)

func trackedKeys(rl *LocalRateLimiter) int {
	total := 0
	for _, s := range rl.shards {
		s.mu.RLock()
		total += len(s.limiters)
		s.mu.RUnlock()
	}
	return total
}

// Rate-limit keys are attacker-controlled (client IP, JA4H, fingerprint), so a
// flood of distinct keys must not grow the map without limit.
func TestRateLimiterBoundsTrackedKeys(t *testing.T) {
	rl := NewRateLimiter(rate.Limit(1), 1)
	t.Cleanup(rl.Close)

	const flood = 1 << 18 // four times the cap
	for i := range flood {
		rl.getLimiter("10.0."+strconv.Itoa(i>>8&0xff)+"."+strconv.Itoa(i&0xff)+"#"+strconv.Itoa(i), 50)
	}
	cap := rateLimiterShards * rateLimiterMaxEntriesPerShard
	if got := trackedKeys(rl); got > cap {
		t.Fatalf("%d distinct keys are tracked after a flood of %d; cap is %d", got, flood, cap)
	}

	// A key that arrives after the flood is still limited.
	lim := rl.getLimiter("198.51.100.7", 50)
	if !lim.Allow() || lim.Allow() {
		t.Fatal("a fresh key after the flood must get exactly its burst")
	}
}

// ApplyRouteMiddlewares builds a new limiter for every chain rebuild and never
// closes the old one, so anything a constructor starts in the background lives
// for the rest of the process.
func TestNewRateLimiterStartsNoBackgroundGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	limiters := make([]*LocalRateLimiter, 0, 200)
	for range 200 {
		limiters = append(limiters, NewRateLimiter(rate.Limit(1), 1))
	}
	after := runtime.NumGoroutine()
	for _, rl := range limiters {
		rl.Close()
	}
	if grew := after - before; grew >= 100 {
		t.Fatalf("building 200 limiters started %d goroutines; every chain rebuild leaks them", grew)
	}
}
