// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"maps"
	"sync/atomic"
	"testing"
)

type picker interface{ NextState() *targetState }

func tally(t *testing.T, lb picker, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	for range n {
		s := lb.NextState()
		if s == nil {
			t.Fatal("no target while some are alive")
		}
		got[s.url]++
	}
	return got
}

// TestRoundRobinSpreadsADeadTargetsShare: with one target down, round robin
// scanned forward from the dead target's turn to the next live one, so that
// one neighbour took the dead target's whole share -- twice the load of the
// others, on the backend least likely to want it during a partial outage.
func TestRoundRobinSpreadsADeadTargetsShare(t *testing.T) {
	for _, tc := range []struct {
		name string
		urls []string
		dead []string
	}{
		{"one of three down", []string{"http://a", "http://b", "http://c"}, []string{"http://b"}},
		{"two of four down", []string{"http://a", "http://b", "http://c", "http://d"}, []string{"http://b", "http://c"}},
		{"one of four down", []string{"http://a", "http://b", "http://c", "http://d"}, []string{"http://a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lb := NewRoundRobinLB(tc.urls)
			for _, u := range tc.dead {
				lb.SetAlive(u, false)
			}
			alive := len(tc.urls) - len(tc.dead)
			rounds := 60 * alive * len(tc.urls)
			want := map[string]int{}
			for _, u := range tc.urls {
				want[u] = rounds / alive
			}
			for _, u := range tc.dead {
				delete(want, u)
			}
			if got := tally(t, lb, rounds); !maps.Equal(got, want) {
				t.Errorf("%d requests = %v, want %v", rounds, got, want)
			}
		})
	}
}

// TestLeastConnSpreadsTies: least-connections broke every tie in favour of the
// first target, and at low concurrency every target is tied at zero -- so one
// backend took all the traffic until requests started overlapping.
func TestLeastConnSpreadsTies(t *testing.T) {
	lb := NewLeastConnLB([]string{"http://a", "http://b", "http://c"})
	want := map[string]int{"http://a": 100, "http://b": 100, "http://c": 100}
	if got := tally(t, lb, 300); !maps.Equal(got, want) {
		t.Errorf("300 sequential requests = %v, want %v", got, want)
	}
}

// TestLeastConnStillPrefersTheLeastLoaded keeps the tie-break from becoming a
// round robin.
func TestLeastConnStillPrefersTheLeastLoaded(t *testing.T) {
	lb := NewLeastConnLB([]string{"http://a", "http://b", "http://c"})
	for _, s := range *lb.targetsPtr.Load() {
		if s.url != "http://b" {
			atomic.AddInt32(&s.activeConn, 5)
		}
	}
	if got := tally(t, lb, 30); got["http://b"] != 30 {
		t.Errorf("30 requests with b the only idle target = %v, want all to b", got)
	}
}
