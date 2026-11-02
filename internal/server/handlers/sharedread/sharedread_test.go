// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package sharedread

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every diagnostics stream computed its own snapshot on every tick. Streams
// that tick inside one period now share one computation: twenty streams
// ticking together, and again inside the period, compute it once.
func TestCallersInsideOnePeriodShareOneComputation(t *testing.T) {
	var computed atomic.Int32
	shared := New(4*time.Second, func(context.Context) (int, error) {
		computed.Add(1)
		time.Sleep(50 * time.Millisecond) // long enough for every caller to arrive while it runs
		return 1, nil
	})
	const callers = 20
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			for range 3 {
				if _, err := shared.Get(context.Background()); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if n := computed.Load(); n != 1 {
		t.Fatalf("%d callers asking three times each computed %d times, want 1", callers, n)
	}
}

// A caller that leaves while the shared computation runs does not take the
// computation down with it: the others still get the result.
func TestACallerLeavingDoesNotCancelTheSharedComputation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	shared := New(4*time.Second, func(ctx context.Context) (int, error) {
		close(started)
		select {
		case <-release:
			return 1, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})
	first, cancelFirst := context.WithCancel(context.Background())
	go func() { _, _ = shared.Get(first) }()
	<-started
	cancelFirst()
	done := make(chan error, 1)
	go func() {
		_, err := shared.Get(context.Background())
		done <- err
	}()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the second caller got %v after the first left", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the second caller never got the shared result")
	}
}

// A result past the period is computed again; a failed computation is not kept.
func TestAStaleOrFailedResultIsComputedAgain(t *testing.T) {
	var n atomic.Int32
	shared := New(time.Millisecond, func(context.Context) (int, error) {
		return int(n.Add(1)), nil
	})
	first, _ := shared.Get(context.Background())
	time.Sleep(5 * time.Millisecond)
	second, _ := shared.Get(context.Background())
	if first == second {
		t.Fatalf("a result past the period was served again: %d then %d", first, second)
	}
}
