// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package lockout

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// trackerByteBound is what a Tracker at DefaultBounds may hold, however long
// the names it is handed (ADR 0053). Measured at about 4 MiB.
const trackerByteBound = 8 << 20

// heapInUse is the live heap after a full collection.
func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// TestLongUsernamesCannotGrowTheTrackerPastItsByteBound is MGMT-N3's memory
// half. The tables were bounded by entry count and keyed by the username the
// caller typed, so a flood of invented names as long as the public body limit
// allows (64 KiB) kept every one of them: 16,384 pairs of 64 KiB is a GiB per
// tracker, measured at 1,029 MiB. The names here are 4 KiB, enough to put the
// unfixed tracker at eight times the bound without the test needing a GiB.
func TestLongUsernamesCannotGrowTheTrackerPastItsByteBound(t *testing.T) {
	tr := New(DefaultBounds)
	pad := strings.Repeat("x", 4<<10)
	before := heapInUse()
	// Twice the pair table, so every slot is filled and eviction has run.
	for i := range 2 * DefaultBounds.Pairs {
		// A fresh string each time, as each request's decoded body is.
		name := strconv.Itoa(i) + pad
		tr.Fail(name, Prefix("203.0.113."+strconv.Itoa(i%250)))
	}
	after := heapInUse()
	runtime.KeepAlive(tr)
	held := int64(after) - int64(before)
	t.Logf("tracker holds %d KiB after %d long-name failures", held>>10, 2*DefaultBounds.Pairs)
	if held > trackerByteBound {
		t.Fatalf("a tracker flooded with 4 KiB usernames holds %d MiB, over its %d MiB bound: "+
			"its keys are the caller's text, not a fixed size", held>>20, trackerByteBound>>20)
	}
}

// TestHashedKeysStillSeparateAccountsAndSources: a fixed-size key must still
// be the account and the source, so one name's lock does not reach another.
func TestHashedKeysStillSeparateAccountsAndSources(t *testing.T) {
	tr, _ := newTestTracker(DefaultBounds)
	long := strings.Repeat("a", 4<<10)
	src := Prefix("203.0.113.9")
	for range PairLimit {
		tr.Fail(long, src)
	}
	if got := tr.Check(long, src); got != PairLocked {
		t.Fatalf("the long name after %d failures: %v, want PairLocked", PairLimit, got)
	}
	if got := tr.Check(long+"b", src); got != Allow {
		t.Errorf("a different name from the same source: %v, want Allow", got)
	}
	if got := tr.Check(long, Prefix("198.51.100.7")); got != Allow {
		t.Errorf("the same name from another source: %v, want Allow", got)
	}
}
