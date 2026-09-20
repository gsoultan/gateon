// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package traffic

import (
	"strconv"
	"testing"
	"time"
)

// This one reaches into cacheStore directly rather than going through the
// factory, so it moved here with the type it tests. Its siblings in
// package middleware build the middleware the way ApplyRouteMiddlewares does
// and have to stay where the factory is.

func TestCacheStoreOrderIsBoundedAcrossExpiry(t *testing.T) {
	s := &cacheStore{entries: make(map[string]*cacheEntry), max: 4, maxBody: 1024}
	for i := range 10_000 {
		key := "k" + strconv.Itoa(i%3) // stays under max, so count-based eviction never runs
		s.set(key, &cacheEntry{body: []byte("v"), expireAt: time.Now().Add(-time.Second)})
		if s.get(key) != nil {
			t.Fatal("an expired entry must not be returned")
		}
	}
	if len(s.order) > cacheOrderSlack*s.max {
		t.Fatalf("order index holds %d keys for %d live entries (cap %d): it grows on every expire-and-refill cycle", len(s.order), len(s.entries), s.max)
	}
}
