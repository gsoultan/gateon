// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import "testing"

// The two threat queries size their result slice with min(limit, 100), and
// make() panics on a negative capacity rather than treating it as zero. They
// had drifted: the Lite variant guarded a nil store, a non-positive limit and a
// negative offset; GetSecurityThreats guarded only the offset — so the bound
// that can end a goroutine was the one left open, and the nil dereference was
// one line below it.
//
// No reachable caller passed a negative: the API service clamps first. This
// makes the sink safe independently of its callers rather than patching a live
// bug, and puts the rule in one place so the two cannot diverge again.

func TestClampThreatBounds(t *testing.T) {
	tests := []struct {
		name                  string
		limit, offset         int
		wantLimit, wantOffset int
	}{
		{name: "ordinary values pass through", limit: 50, offset: 10, wantLimit: 50, wantOffset: 10},
		{name: "zero limit takes the default", limit: 0, wantLimit: defaultThreatQueryLimit},
		{name: "negative limit takes the default", limit: -1, wantLimit: defaultThreatQueryLimit},
		{name: "the most negative int32 does not survive", limit: -2147483648, wantLimit: defaultThreatQueryLimit},
		{name: "oversized limit is capped", limit: 1 << 30, wantLimit: maxThreatQueryLimit},
		{name: "exactly at the cap", limit: maxThreatQueryLimit, wantLimit: maxThreatQueryLimit},
		{name: "negative offset floors at zero", limit: 10, offset: -5, wantLimit: 10, wantOffset: 0},
		{name: "both negative", limit: -7, offset: -7, wantLimit: defaultThreatQueryLimit, wantOffset: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLimit, gotOffset := clampThreatBounds(tt.limit, tt.offset)
			if gotLimit != tt.wantLimit {
				t.Errorf("limit: got %d, want %d", gotLimit, tt.wantLimit)
			}
			if gotOffset != tt.wantOffset {
				t.Errorf("offset: got %d, want %d", gotOffset, tt.wantOffset)
			}
		})
	}
}

// The property that matters: for any input at all, the result is a capacity
// make() will accept.
func TestClampedBoundsAreAlwaysAllocatable(t *testing.T) {
	for _, in := range []int{-2147483648, -1000, -1, 0, 1, 99, 100, 1000, 1 << 30, 1<<62 - 1} {
		limit, offset := clampThreatBounds(in, in)
		if limit <= 0 {
			t.Errorf("clampThreatBounds(%d) gave limit %d", in, limit)
		}
		if offset < 0 {
			t.Errorf("clampThreatBounds(%d) gave offset %d", in, offset)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("make() panicked for input %d: %v", in, r)
				}
			}()
			_ = make([]*SecurityThreat, 0, min(limit, 100))
		}()
	}
}
