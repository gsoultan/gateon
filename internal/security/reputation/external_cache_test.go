// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package reputation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestScoreCacheIsBounded: the key is the client's IP, so the entry set is the
// set of addresses attacking the gateway. A sync.Map with no eviction grew
// fastest exactly when it most needed to survive.
func TestScoreCacheIsBounded(t *testing.T) {
	c := newScoreCache()

	// Asserted through get/put rather than by reading lru.Len(), so the test
	// describes behaviour the caller can observe: with an unbounded map the
	// first address is still there at the end, and that is the bug.
	const oldest = "198.51.100.1"
	c.put(oldest, 42)

	const overfill = externalScoreCacheSize + 5000
	for i := range overfill {
		c.put(fmt.Sprintf("203.0.113.%d.%d", i/256, i%256), i%100)
	}
	newest := fmt.Sprintf("203.0.113.%d.%d", (overfill-1)/256, (overfill-1)%256)

	if _, ok := c.get(oldest); ok {
		t.Errorf("the first address cached is still held after %d others; "+
			"nothing evicts, so an attacker rotating source addresses grows "+
			"this without limit", overfill)
	}
	if _, ok := c.get(newest); !ok {
		t.Error("the most recently cached address was evicted; the bound is " +
			"dropping the entries it should be keeping")
	}
	if got := c.lru.Len(); got > externalScoreCacheSize {
		t.Errorf("cache holds %d entries, want at most %d", got, externalScoreCacheSize)
	}
}

// TestScoreCacheExpires: a cached verdict must not outlive its usefulness. The
// old cache pinned a provider's answer for the life of the process, so an
// address that was clean at first contact stayed clean however it behaved
// afterwards.
func TestScoreCacheExpires(t *testing.T) {
	c := newScoreCacheWithTTL(20 * time.Millisecond)
	c.put("203.0.113.9", 95)

	if score, ok := c.get("203.0.113.9"); !ok || score != 95 {
		t.Fatalf("fresh entry: got (%d, %v), want (95, true)", score, ok)
	}

	time.Sleep(40 * time.Millisecond)

	if score, ok := c.get("203.0.113.9"); ok {
		t.Errorf("an entry past its TTL was served (score %d); external threat "+
			"intelligence becomes a first-contact snapshot", score)
	}
}

// TestAbuseIPDBRefetchesAfterTTL drives the property through the client, so it
// covers the wiring and not only the cache type: one upstream call while the
// entry is fresh, a second once it is not.
func TestAbuseIPDBRefetchesAfterTTL(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":73}}`))
	}))
	defer srv.Close()

	c := NewAbuseIPDBClient("test-key")
	c.BaseURL = srv.URL
	c.cache = newScoreCacheWithTTL(20 * time.Millisecond)

	ctx := t.Context()
	for range 3 {
		score, err := c.CheckIP(ctx, "203.0.113.10")
		if err != nil {
			t.Fatalf("CheckIP: %v", err)
		}
		if score != 73 {
			t.Fatalf("score = %d, want 73", score)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("three lookups inside the TTL made %d upstream calls, want 1", got)
	}

	time.Sleep(40 * time.Millisecond)

	if _, err := c.CheckIP(ctx, "203.0.113.10"); err != nil {
		t.Fatalf("CheckIP after TTL: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("a lookup past the TTL made %d upstream calls in total, want 2; "+
			"the cached verdict never refreshes", got)
	}
}
