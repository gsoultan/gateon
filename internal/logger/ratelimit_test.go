// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPerSecondHoldsWhenEventsArriveOutOfOrder is OPS-N2. The access-log cap
// was keyed on the time each request started and reset its count whenever the
// time it was handed differed from the window it held -- forwards or
// backwards. A slow request finishing beside fast ones moved the window back,
// the next fast one moved it forward again, and each move started the count
// over: 737 lines a second went through a cap of 100. Alternating the two
// stamps here, two windows' worth (twenty) is the most that may pass.
func TestPerSecondHoldsWhenEventsArriveOutOfOrder(t *testing.T) {
	var p PerSecond
	p.SetMax(10)
	base := time.Now()
	earlier, later := base.Add(time.Second), base.Add(2*time.Second)
	allowed := 0
	for i := range 1000 {
		at := later
		if i%2 == 1 {
			at = earlier
		}
		if p.Allow(at) {
			allowed++
		}
	}
	if allowed > 20 {
		t.Fatalf("%d of 1000 events allowed across two windows under a cap of 10 a second", allowed)
	}
}

// TestPerSecondIsExactUnderConcurrency: every caller in one window, from many
// goroutines, and exactly the cap gets through -- moving to a window and
// counting in it are one step, so no count is lost to a reset.
func TestPerSecondIsExactUnderConcurrency(t *testing.T) {
	var p PerSecond
	p.SetMax(100)
	at := time.Now().Add(5 * time.Second)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				if p.Allow(at) {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 100 {
		t.Fatalf("%d events allowed in one window under a cap of 100", got)
	}
}

// TestPerSecondOpensEachNewWindowAndALiftedCapAllowsAll covers the rest of
// the contract: the next window admits again, and a cap of zero admits all.
func TestPerSecondOpensEachNewWindowAndALiftedCapAllowsAll(t *testing.T) {
	var p PerSecond
	p.SetMax(2)
	base := time.Now()
	admitted := func(at time.Time) (n int) {
		for range 3 {
			if p.Allow(at) {
				n++
			}
		}
		return n
	}
	if n := admitted(base); n != 2 {
		t.Fatalf("a cap of two admitted %d of 3 events in a window", n)
	}
	if n := admitted(base.Add(time.Second)); n != 2 {
		t.Fatalf("the next window admitted %d of 3 events, want 2 of its own", n)
	}
	p.SetMax(0)
	for range 100 {
		if !p.Allow(base) {
			t.Fatal("a cap of zero refused an event")
		}
	}
	if !p.Allow(base.Add(-time.Hour)) {
		t.Fatal("an event before the epoch was refused under no cap")
	}
}

// captureL points L at a buffer for the test.
func captureL(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := L.p.Load()
	L.set(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { L.p.Store(prev) })
	return &buf
}

// TestLineLimiterWritesTheFirstLinesAndReportsTheRestPerKey: three lines a
// second are written, every other one is counted under its key, and after the
// interval the next call reports each key's count once.
func TestLineLimiterWritesTheFirstLinesAndReportsTheRestPerKey(t *testing.T) {
	buf := captureL(t)
	l := NewLineLimiter(LineLimit{
		Level: slog.LevelError, Summary: "lines left out", PerSecond: 3, Every: 10 * time.Second,
		Labels: [2]string{"route", "target"},
	})
	base := time.Now()
	written := 0
	for i := range 50 {
		if l.Allow(base) {
			written++
			continue
		}
		l.Skip(base, "r1", []string{"a", "b"}[i%2])
	}
	if written != 3 {
		t.Fatalf("wrote %d of 50 lines under a cap of 3", written)
	}
	if strings.Contains(buf.String(), "lines left out") {
		t.Fatalf("reported before the interval passed:\n%s", buf.String())
	}
	l.Allow(base.Add(11 * time.Second))
	out := buf.String()
	if got := strings.Count(out, "lines left out"); got != 2 {
		t.Fatalf("reported %d lines, want one per key (2):\n%s", got, out)
	}
	for _, want := range []string{"target=a not_written=23", "target=b not_written=24", "level=ERROR"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	buf.Reset()
	l.Allow(base.Add(30 * time.Second))
	if buf.Len() != 0 {
		t.Errorf("reported again with nothing left out:\n%s", buf.String())
	}
}

// TestLineLimiterBoundsItsKeys: past lineLimiterMaxKeys keys, lines are
// counted under one overflow key rather than growing the map.
func TestLineLimiterBoundsItsKeys(t *testing.T) {
	buf := captureL(t)
	l := NewLineLimiter(LineLimit{Level: slog.LevelInfo, Summary: "left out", PerSecond: 1, Every: time.Second,
		Labels: [2]string{"k", "v"}})
	now := time.Now()
	for i := range lineLimiterMaxKeys + 10 {
		l.Skip(now, "key", strings.Repeat("x", i+1))
	}
	if len(l.pending) != lineLimiterMaxKeys || l.overflow != 10 {
		t.Fatalf("pending keys %d, overflow %d; want %d and 10", len(l.pending), l.overflow, lineLimiterMaxKeys)
	}
	l.Flush()
	if !strings.Contains(buf.String(), `k=(other) v=(other) not_written=10`) {
		t.Errorf("the overflow was not reported:\n%s", buf.String())
	}
	if l.pendingN.Load() != 0 || l.pending != nil {
		t.Error("Flush left lines pending")
	}
}

// BenchmarkPerSecondAllow is the cost on a line that is written: one load and
// one compare-and-swap, no allocation.
func BenchmarkPerSecondAllow(b *testing.B) {
	var p PerSecond
	p.SetMax(countMask)
	now := time.Now()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.Allow(now)
		}
	})
}
