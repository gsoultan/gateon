// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package syncutil

import (
	"runtime/debug"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
)

// Restart delays after a supervised goroutine panics: the first restart waits
// firstRestartDelay, each later one twice the last, up to maxRestartDelay, so
// a panic that recurs on every run costs a log line a minute, not a busy loop.
const (
	firstRestartDelay = time.Second
	maxRestartDelay   = time.Minute
)

// Supervise runs fn, and runs it again after a panic, until fn returns or done
// is closed. Each panic is logged with name and its stack.
//
// net/http recovers a panic in a handler; nothing recovers one on a goroutine
// the program started itself, and Go ends the process when one panics. The
// background consumers of request data -- the telemetry writer, the anomaly
// detectors, the correlation engine -- handle strings clients chose, so a bug
// in any of them was a remote kill switch for every listener (2026-11-20
// audit, L8). Under Supervise it costs that component one run.
//
// Run it on its own goroutine: go syncutil.Supervise(ctx.Done(), "name", fn).
func Supervise(done <-chan struct{}, name string, fn func()) {
	delay := firstRestartDelay
	for runRecovered(name, fn) {
		timer := time.NewTimer(delay)
		select {
		case <-done:
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(2*delay, maxRestartDelay)
		logger.L.LogWarn("restarting a background task after a panic", "task", name)
	}
}

// Recover, deferred at the top of a goroutine, ends that goroutine instead of
// the process when it panics, and logs name and the stack. For one-shot work;
// a loop that should keep running belongs under Supervise.
func Recover(name string) {
	if p := recover(); p != nil {
		logPanic(name, p)
	}
}

// runRecovered runs fn and reports whether it panicked.
func runRecovered(name string, fn func()) (panicked bool) {
	defer func() {
		if p := recover(); p != nil {
			logPanic(name, p)
			panicked = true
		}
	}()
	fn()
	return false
}

func logPanic(name string, p any) {
	logger.L.LogError("background task panicked; the process keeps running",
		"task", name, "panic", p, "stack", string(debug.Stack()))
}
