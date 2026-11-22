// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package syncutil

import (
	"sync"
	"testing"
	"testing/synctest"
)

// TestSuperviseRestartsAfterAPanic: a supervised task that panics runs again,
// and Supervise returns once the task returns on its own.
func TestSuperviseRestartsAfterAPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runs := 0
		Supervise(make(chan struct{}), "test task", func() {
			runs++
			if runs < 3 {
				panic("boom")
			}
		})
		if runs != 3 {
			t.Fatalf("the task ran %d times, want 3 (two panics, then a clean return)", runs)
		}
	})
}

// TestSuperviseStopsWhenDone: a task that panics every time stops being
// restarted once done is closed.
func TestSuperviseStopsWhenDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		var once sync.Once
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			Supervise(done, "test task", func() {
				once.Do(func() { close(done) })
				panic("boom")
			})
		}()
		synctest.Wait()
		select {
		case <-returned:
		default:
			t.Fatal("Supervise kept restarting a task after done was closed")
		}
	})
}

// TestRecoverContainsAGoroutinePanic: a goroutine that defers Recover ends on
// a panic instead of taking the test binary with it.
func TestRecoverContainsAGoroutinePanic(t *testing.T) {
	var wg sync.WaitGroup
	wg.Go(func() {
		defer Recover("test goroutine")
		panic("boom")
	})
	wg.Wait()
}
