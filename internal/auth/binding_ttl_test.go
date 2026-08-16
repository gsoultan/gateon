// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"sync"
	"testing"
	"time"
)

// The binding cache is per process and invalidation is a local map delete, so
// across instances sharing one database a revocation reached only the instance
// that handled it. With no expiry the others kept serving the old binding
// forever — disabling an account took effect on one instance and nowhere else.
// These tests pin the expiry that bounds it.
//
// Time is injected rather than slept: a 30-second TTL is not something a test
// suite can wait out, and sleeping for timing is a qa veto anyway.

func fixedClock(t time.Time) (*time.Time, func() time.Time) {
	now := &t
	return now, func() time.Time { return *now }
}

func TestBindingCache_ServesWithinTTL(t *testing.T) {
	c := newBindingCacheWithTTL(30 * time.Second)
	now, clock := fixedClock(time.Unix(1_760_000_000, 0))
	c.now = clock

	c.put("user-1", "binding-a")

	*now = now.Add(29 * time.Second)
	got, ok := c.get("user-1")
	if !ok || got != "binding-a" {
		t.Fatalf("get = (%q, %v) inside the TTL, want (\"binding-a\", true)", got, ok)
	}
}

// The property that actually fixes the multi-instance gap: past the TTL the
// entry is reported absent, so the caller reloads from the database and sees the
// revocation another instance wrote.
func TestBindingCache_ExpiresAfterTTL(t *testing.T) {
	c := newBindingCacheWithTTL(30 * time.Second)
	now, clock := fixedClock(time.Unix(1_760_000_000, 0))
	c.now = clock

	c.put("user-1", "binding-a")

	*now = now.Add(30 * time.Second) // exactly at the boundary
	if _, ok := c.get("user-1"); ok {
		t.Fatal("entry still served at exactly the TTL boundary; staleness must be bounded")
	}

	*now = now.Add(time.Hour)
	if _, ok := c.get("user-1"); ok {
		t.Fatal("entry still served an hour past the TTL")
	}
}

// A local invalidation must still be immediate — the TTL is a ceiling on
// staleness, not a delay imposed on the instance that did the work.
func TestBindingCache_InvalidateIsImmediate(t *testing.T) {
	c := newBindingCacheWithTTL(time.Hour)
	now, clock := fixedClock(time.Unix(1_760_000_000, 0))
	c.now = clock

	c.put("user-1", "binding-a")
	c.invalidate("user-1")

	if _, ok := c.get("user-1"); ok {
		t.Fatal("invalidate did not drop the entry")
	}
	_ = now
}

// Re-putting refreshes the deadline, so an account in continuous use does not
// fall out mid-request and pay a database read on a fixed cadence.
func TestBindingCache_PutRefreshesTheDeadline(t *testing.T) {
	c := newBindingCacheWithTTL(30 * time.Second)
	now, clock := fixedClock(time.Unix(1_760_000_000, 0))
	c.now = clock

	c.put("user-1", "binding-a")
	*now = now.Add(20 * time.Second)
	c.put("user-1", "binding-a")

	*now = now.Add(20 * time.Second) // 40s from the first put, 20s from the second
	if _, ok := c.get("user-1"); !ok {
		t.Fatal("entry expired despite being refreshed")
	}
}

func TestBindingCache_MissingEntry(t *testing.T) {
	c := newBindingCacheWithTTL(30 * time.Second)
	if _, ok := c.get("never-seen"); ok {
		t.Fatal("reported a hit for an id never put")
	}
}

func TestNewBindingCacheWithTTL_RejectsNonPositive(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		if got := newBindingCacheWithTTL(ttl).ttl; got != DefaultBindingTTL {
			t.Fatalf("ttl %v produced %v, want the default %v", ttl, got, DefaultBindingTTL)
		}
	}
}

func TestBindingTTLFromEnv(t *testing.T) {
	tests := []struct {
		name string
		set  string
		want time.Duration
	}{
		{"unset", "", DefaultBindingTTL},
		{"valid", "5", 5 * time.Second},
		{"padded", "  90  ", 90 * time.Second},
		{"zero falls back", "0", DefaultBindingTTL},
		{"negative falls back", "-10", DefaultBindingTTL},
		{"garbage falls back", "soon", DefaultBindingTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(BindingTTLEnv, tt.set)
			if got := bindingTTLFromEnv(); got != tt.want {
				t.Fatalf("bindingTTLFromEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The cache sits on the authenticated request path, so concurrent readers and
// the writer must not race. Run with -race.
func TestBindingCache_ConcurrentAccess(t *testing.T) {
	c := newBindingCacheWithTTL(time.Hour)

	var wg sync.WaitGroup
	for w := range 16 {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			id := string(rune('a' + w%8))
			for range 200 {
				c.put(id, "binding")
				_, _ = c.get(id)
				c.invalidate(id)
			}
		}(w)
	}
	wg.Wait()
}
