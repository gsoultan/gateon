// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import (
	"io"
	"log/slog"
	"sync"
	"testing"
)

// TestSwapIsSafeWhileLogging: a test captures L's output while a goroutine
// an earlier test left behind is still logging through it. Replacing L itself
// raced against that goroutine; Swap replaces the logger inside the shim, which
// the race detector must accept.
func TestSwapIsSafeWhileLogging(t *testing.T) {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				L.LogInfo("still logging")
			}
		}
	})
	for range 100 {
		prev := L.Swap(slog.New(slog.NewTextHandler(io.Discard, nil)))
		L.Swap(prev)
	}
	close(stop)
	wg.Wait()
}
