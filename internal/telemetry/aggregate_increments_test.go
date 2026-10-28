// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"
)

// aggregateIncrements formats a batch's day once rather than per increment,
// so it must notice the day changing inside a batch: a flush that straddles
// midnight UTC writes yesterday's requests to yesterday's row and today's to
// today's, and a return to the first day is that day again.
func TestAggregateIncrementsSplitsABatchAtMidnight(t *testing.T) {
	midnight := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	before, after := midnight.Add(-time.Second), midnight.Add(time.Second)
	batch := []increment{
		{host: "h", path: "/p", atTime: before, bytesTotal: 1},
		{host: "h", path: "/p", atTime: after, bytesTotal: 2},
		{host: "h", path: "/p", atTime: before, bytesTotal: 4},
		// Not UTC: the day is UTC's, as it always was.
		{host: "h", path: "/p", atTime: after.In(time.FixedZone("UTC-5", -5*3600)), bytesTotal: 8},
	}
	got := aggregateIncrements(batch)
	if len(got) != 2 {
		t.Fatalf("%d rows, want one per day: %v", len(got), got)
	}
	for day, wantBytes := range map[string]uint64{"2026-10-27": 1 + 4, "2026-10-28": 2 + 8} {
		c := got[statKey{day: day, host: "h", path: "/p"}]
		if c == nil {
			t.Fatalf("no row for %s: %v", day, got)
		}
		if c.bytes != wantBytes {
			t.Errorf("%s holds %v bytes, want %d", day, c.bytes, wantBytes)
		}
	}
}
