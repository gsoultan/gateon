// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package lookupgate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// margin is what a wait may take past its deadline on a loaded CI runner.
const margin = 450 * time.Millisecond

// stuckRead is a read that ignores its context and waits for release, as
// lib/pq does against a stopped server. It counts reads, and the most running
// at once.
type stuckRead struct {
	release chan struct{}
	reads   atomic.Int64
	running atomic.Int64
	peak    atomic.Int64
	once    sync.Once
	answer  int
}

func newStuckRead(t *testing.T) *stuckRead {
	r := &stuckRead{release: make(chan struct{}), answer: 7}
	t.Cleanup(r.free)
	return r
}

func (r *stuckRead) free() { r.once.Do(func() { close(r.release) }) }

func (r *stuckRead) read(_ context.Context, _ string) (int, error) {
	r.reads.Add(1)
	n := r.running.Add(1)
	defer r.running.Add(-1)
	for p := r.peak.Load(); n > p && !r.peak.CompareAndSwap(p, n); p = r.peak.Load() {
	}
	<-r.release
	return r.answer, nil
}

// A caller waits no longer than the deadline, though the read it waits for
// ignores its context and never returns by itself.
func TestDoReturnsAtTheDeadlineThoughTheReadIgnoresIt(t *testing.T) {
	r := newStuckRead(t)
	g := New(NewSlots(4), 50*time.Millisecond, r.read)
	t.Cleanup(func() { r.free(); g.Wait() })
	start := time.Now()
	_, err := g.Do(context.Background(), "198.51.100.1")
	if took := time.Since(start); took > 50*time.Millisecond+margin {
		t.Fatalf("Do took %v against a 50ms deadline", took)
	}
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
}

// The caller's own context ends its wait too: a client that went away does not
// hold a goroutine until the deadline.
func TestTheCallersContextEndsTheWait(t *testing.T) {
	r := newStuckRead(t)
	g := New(NewSlots(4), time.Hour, r.read)
	t.Cleanup(func() { r.free(); g.Wait() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := g.Do(ctx, "k"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if took := time.Since(start); took > 30*time.Millisecond+margin {
		t.Fatalf("Do took %v after its caller's context ended at 30ms", took)
	}
}

// A read that answers in time is the answer.
func TestDoReturnsTheReadsAnswer(t *testing.T) {
	r := newStuckRead(t)
	r.free()
	g := New(NewSlots(1), time.Second, r.read)
	t.Cleanup(func() { r.free(); g.Wait() })
	if v, err := g.Do(context.Background(), "k"); err != nil || v != 7 {
		t.Fatalf("Do = %d, %v; want 7, nil", v, err)
	}
}

// Concurrent lookups of one key share one read: a slow database is asked once
// per key, not once per request. While the read is outstanding -- past its
// deadline included -- every caller joins it.
func TestConcurrentLookupsOfOneKeyShareOneRead(t *testing.T) {
	r := newStuckRead(t)
	g := New(NewSlots(4), 50*time.Millisecond, r.read)
	t.Cleanup(func() { r.free(); g.Wait() })
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() { _, _ = g.Do(context.Background(), "198.51.100.2") })
	}
	wg.Wait()
	if n := r.reads.Load(); n != 1 {
		t.Fatalf("64 concurrent lookups of one key made %d reads, want 1", n)
	}
}

// No more reads run at once than there are slots, across every gate sharing
// them; a lookup past the bound is answered ErrSaturated at once rather than
// queued behind the others.
func TestInFlightReadsNeverExceedTheSlots(t *testing.T) {
	r := newStuckRead(t)
	slots := NewSlots(3)
	a := New(slots, 200*time.Millisecond, r.read)
	b := New(slots, 200*time.Millisecond, r.read)
	t.Cleanup(func() { r.free(); a.Wait() })
	t.Cleanup(func() { r.free(); b.Wait() })
	var saturated atomic.Int64
	var wg sync.WaitGroup
	for i := range 40 {
		g := a
		if i%2 == 1 {
			g = b
		}
		wg.Go(func() {
			start := time.Now()
			_, err := g.Do(context.Background(), fmt.Sprintf("198.51.100.%d", i))
			if errors.Is(err, ErrSaturated) {
				saturated.Add(1)
				if took := time.Since(start); took > margin {
					t.Errorf("a saturated lookup waited %v; it must not queue", took)
				}
			}
		})
	}
	wg.Wait()
	if p := r.peak.Load(); p > 3 {
		t.Fatalf("%d reads ran at once; the bound is 3", p)
	}
	if n := r.reads.Load(); n != 3 || saturated.Load() != 37 {
		t.Fatalf("%d reads started and %d lookups saturated; want 3 and 37", n, saturated.Load())
	}
	if slots.InFlight() != 3 || slots.Cap() != 3 {
		t.Fatalf("slots %d/%d held; reads that ignore their context keep theirs until they end", slots.InFlight(), slots.Cap())
	}
	r.free()
	a.Wait()
	b.Wait()
	if slots.InFlight() != 0 {
		t.Fatalf("%d slots still held after every read ended", slots.InFlight())
	}
}

// Refresh starts one read nobody waits for, and joins it rather than starting
// another.
func TestRefreshStartsOneReadAndDoesNotWait(t *testing.T) {
	r := newStuckRead(t)
	g := New(NewSlots(2), time.Hour, r.read)
	t.Cleanup(func() { r.free(); g.Wait() })
	for range 10 {
		if !g.Refresh("k") {
			t.Fatal("Refresh found no read running and none started")
		}
	}
	if n := r.reads.Load(); n > 1 {
		t.Fatalf("10 refreshes of one key started %d reads, want 1", n)
	}
	r.free()
	g.Wait()
	if n := r.reads.Load(); n != 1 {
		t.Fatalf("%d reads, want 1", n)
	}
}

// A deadline below a millisecond is a millisecond: never none at all.
func TestTimeoutIsNeverZero(t *testing.T) {
	g := New(NewSlots(1), 0, func(context.Context, string) (int, error) { return 0, nil })
	if g.Timeout() != time.Millisecond {
		t.Fatalf("timeout %v, want 1ms", g.Timeout())
	}
	if s := NewSlots(0); s.Cap() != 1 {
		t.Fatalf("NewSlots(0) holds %d, want 1", s.Cap())
	}
}

// A caller whose context has already ended -- a request that spent its lookup
// budget on an earlier lookup -- is answered at once and starts no read.
func TestDoWithAnEndedContextStartsNothing(t *testing.T) {
	r := newStuckRead(t)
	g := New(NewSlots(2), time.Hour, r.read)
	t.Cleanup(func() { r.free(); g.Wait() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Do(ctx, "k"); !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	// A read started holds its slot from the moment it is started.
	if n := g.slots.InFlight(); n != 0 {
		t.Fatalf("a caller with nothing left to wait started %d reads", n)
	}
}
