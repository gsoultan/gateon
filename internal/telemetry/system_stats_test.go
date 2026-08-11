// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"
)

// The gateway reports its memory and goroutine count from three endpoints:
// /v1/status, /v1/diag/metrics and /v1/diag/sys. They each used to call
// runtime.ReadMemStats themselves, which made them disagree — measured at
// 22,355,312 / 22,006,008 / 22,585,968 bytes for one process sampled inside the
// same second — and made every dashboard poll stop the world to produce the
// discrepancy.
//
// They now read one sample published by the metrics collector. These tests pin
// both halves of that: the published sample is what callers get, and reading it
// twice does not resample.

func TestSystemStatsReportsThePublishedSample(t *testing.T) {
	restore := stashRuntimeSample()
	t.Cleanup(restore)

	lastMemAlloc.Store(4242)
	lastMemSys.Store(9999)
	lastMemTotalAlloc.Store(123456)
	lastGoroutines.Store(77)

	got := GetSystemStats()

	if got.MemoryAllocBytes != 4242 {
		t.Errorf("MemoryAllocBytes = %d, want 4242 (the collector's sample)", got.MemoryAllocBytes)
	}
	if got.MemorySysBytes != 9999 {
		t.Errorf("MemorySysBytes = %d, want 9999", got.MemorySysBytes)
	}
	if got.MemoryTotalAllocBytes != 123456 {
		t.Errorf("MemoryTotalAllocBytes = %d, want 123456", got.MemoryTotalAllocBytes)
	}
	if got.Goroutines != 77 {
		t.Errorf("Goroutines = %d, want 77", got.Goroutines)
	}
}

// Two reads of the same published sample must be identical. If this fails,
// something has gone back to sampling the runtime per call — which is both the
// stop-the-world cost and the reason the endpoints disagreed.
func TestSystemStatsDoesNotResamplePerCall(t *testing.T) {
	restore := stashRuntimeSample()
	t.Cleanup(restore)

	lastMemAlloc.Store(555)
	lastGoroutines.Store(12)

	first := GetSystemStats()
	// Allocate enough that a fresh ReadMemStats would almost certainly differ.
	sink := make([][]byte, 0, 256)
	for i := 0; i < 256; i++ {
		sink = append(sink, make([]byte, 4096))
	}
	_ = sink
	second := GetSystemStats()

	if first.MemoryAllocBytes != second.MemoryAllocBytes {
		t.Errorf("two reads returned different memory (%d then %d); the runtime is being resampled per call",
			first.MemoryAllocBytes, second.MemoryAllocBytes)
	}
	if first.Goroutines != second.Goroutines {
		t.Errorf("two reads returned different goroutine counts (%d then %d)", first.Goroutines, second.Goroutines)
	}
}

// Before the collector's first tick there is nothing published, and reporting a
// process with zero goroutines would be worse than paying for one direct read.
func TestSystemStatsFallsBackBeforeTheFirstCollectorTick(t *testing.T) {
	restore := stashRuntimeSample()
	t.Cleanup(restore)

	lastMemAlloc.Store(0)
	lastMemSys.Store(0)
	lastMemTotalAlloc.Store(0)
	lastGoroutines.Store(0)

	got := GetSystemStats()
	if got.Goroutines <= 0 {
		t.Errorf("Goroutines = %d before the first tick; want a real reading rather than zero", got.Goroutines)
	}
	if got.MemoryAllocBytes == 0 {
		t.Error("MemoryAllocBytes = 0 before the first tick; want a real reading")
	}
}

func TestSystemStatsUptimeTracksStartTime(t *testing.T) {
	restore := stashRuntimeSample()
	t.Cleanup(restore)

	prev := startTime
	startTime = time.Now().Add(-90 * time.Second)
	t.Cleanup(func() { startTime = prev })

	if got := GetSystemStats().UptimeSeconds; got < 89 || got > 95 {
		t.Errorf("UptimeSeconds = %v, want ~90", got)
	}
}

// stashRuntimeSample saves the published sample and returns a restore func, so
// these tests do not leak values into anything else in the package.
func stashRuntimeSample() func() {
	alloc, sys := lastMemAlloc.Load(), lastMemSys.Load()
	total, goroutines := lastMemTotalAlloc.Load(), lastGoroutines.Load()
	return func() {
		lastMemAlloc.Store(alloc)
		lastMemSys.Store(sys)
		lastMemTotalAlloc.Store(total)
		lastGoroutines.Store(goroutines)
	}
}
