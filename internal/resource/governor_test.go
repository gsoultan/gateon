// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package resource

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor blocks until c fires or the test's patience runs out. Every wait in
// this file goes through it, because the test it replaced slept 100ms to "wait
// for one tick" against a five-second ticker: the tick never arrived, and what
// the test actually measured was whichever statements the scheduler reached
// before it returned. That is why this package's coverage swung 17 points
// between CI runs on a single commit.
func waitFor(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// fixed returns a usageFunc reporting a constant, so a pressure branch is
// entered because the test said so and not because the machine was busy.
func fixed(percent float64) usageFunc {
	return func(context.Context) (float64, error) { return percent, nil }
}

func failing(err error) usageFunc {
	return func(context.Context) (float64, error) { return 0, err }
}

// newTestGovernor builds a governor that samples immediately and reports
// whatever the caller wants it to see.
func newTestGovernor(mem, cpu usageFunc) *Governor {
	g := NewGovernor()
	g.interval = time.Millisecond
	g.memUsage = mem
	g.cpuUsage = cpu
	return g
}

// signalHook returns a hook that closes its channel the first time it runs, so
// a test can wait on the hook actually firing rather than on the clock.
func signalHook() (ScavengeHook, <-chan struct{}) {
	fired := make(chan struct{})
	var once atomic.Bool
	return func() {
		if once.CompareAndSwap(false, true) {
			close(fired)
		}
	}, fired
}

func TestHooksFireAboveTheirThreshold(t *testing.T) {
	tests := []struct {
		name     string
		mem, cpu float64
		register func(*Governor, ScavengeHook)
	}{
		{
			name: "memory above 80 percent",
			mem:  memoryPressurePercent + 0.1, cpu: 0,
			register: func(g *Governor, h ScavengeHook) { g.RegisterMemoryHook("scavenge", h) },
		},
		{
			name: "cpu above 90 percent",
			mem:  0, cpu: cpuPressurePercent + 0.1,
			register: func(g *Governor, h ScavengeHook) { g.RegisterCPUHook("scavenge", h) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newTestGovernor(fixed(tt.mem), fixed(tt.cpu))
			hook, fired := signalHook()
			tt.register(g, hook)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go g.Start(ctx)

			waitFor(t, fired, "the scavenge hook to fire")
		})
	}
}

// TestHooksDoNotFireAtOrBelowTheThreshold pins the comparison as strictly
// greater-than. A hook that fires at exactly 80% would scavenge continuously on
// a machine sitting on the line, which costs more than the pressure it answers.
func TestHooksDoNotFireAtOrBelowTheThreshold(t *testing.T) {
	tests := []struct {
		name     string
		mem, cpu float64
	}{
		{"exactly at both thresholds", memoryPressurePercent, cpuPressurePercent},
		{"well below both", 12, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := newTestGovernor(fixed(tt.mem), fixed(tt.cpu))
			var fires atomic.Int64
			count := func() { fires.Add(1) }
			g.RegisterMemoryHook("mem", count)
			g.RegisterCPUHook("cpu", count)

			// check() is called directly: waiting on something that must not
			// happen can only be done with a sleep, and a sleep is what this
			// file exists to remove. One call is enough — Start's only job is
			// to call it on a ticker, and that is covered above.
			g.check(context.Background())

			if n := fires.Load(); n != 0 {
				t.Errorf("hooks fired %d times at mem=%.1f cpu=%.1f, want 0", n, tt.mem, tt.cpu)
			}
		})
	}
}

// TestUnreadableStatsDoNotFireHooks covers the case that made this injectable.
// "Cannot read the gauge" is not "the gauge reads zero": scavenging on a failed
// sample would drop caches across the fleet the moment gopsutil hiccuped.
func TestUnreadableStatsDoNotFireHooks(t *testing.T) {
	g := newTestGovernor(failing(errors.New("read /proc/meminfo: no such file")), failing(errNoCPUSample))
	var fires atomic.Int64
	count := func() { fires.Add(1) }
	g.RegisterMemoryHook("mem", count)
	g.RegisterCPUHook("cpu", count)

	g.check(context.Background())

	if n := fires.Load(); n != 0 {
		t.Errorf("hooks fired %d times on unreadable stats, want 0", n)
	}
}

// TestStartStopsOnContextCancel pins the shutdown path. A monitor goroutine
// that outlives its context is a leak the caller has no handle on.
func TestStartStopsOnContextCancel(t *testing.T) {
	g := newTestGovernor(fixed(0), fixed(0))
	ctx, cancel := context.WithCancel(context.Background())

	stopped := make(chan struct{})
	go func() {
		g.Start(ctx)
		close(stopped)
	}()

	cancel()
	waitFor(t, stopped, "Start to return after its context was cancelled")
}

// TestHooksRunUnlocked is a deadlock regression: a scavenge hook is arbitrary
// caller code, and one that touches the governor would hang forever if the
// hook set were still read-locked while it ran.
func TestHooksRunUnlocked(t *testing.T) {
	g := newTestGovernor(fixed(memoryPressurePercent+5), fixed(0))

	done := make(chan struct{})
	g.RegisterMemoryHook("reentrant", func() {
		// Re-enters the governor from inside the hook.
		g.RegisterMemoryHook("added-from-hook", func() {})
		select {
		case <-done:
		default:
			close(done)
		}
	})

	go g.check(context.Background())
	waitFor(t, done, "a hook that re-enters the governor to complete")
}

func TestGetStatusReportsRegisteredHooksAndPressure(t *testing.T) {
	g := newTestGovernor(fixed(42.5), fixed(17.25))
	g.RegisterMemoryHook("m1", func() {})
	g.RegisterMemoryHook("m2", func() {})
	g.RegisterCPUHook("c1", func() {})

	active, memHooks, cpuHooks, memPressure, cpuPressure := g.GetStatus(context.Background())
	if !active {
		t.Error("active = false, want true")
	}
	if memHooks != 2 || cpuHooks != 1 {
		t.Errorf("hooks = (%d mem, %d cpu), want (2, 1)", memHooks, cpuHooks)
	}
	if memPressure != 42.5 || cpuPressure != 17.25 {
		t.Errorf("pressure = (%.2f, %.2f), want (42.50, 17.25)", memPressure, cpuPressure)
	}
}

// TestGetStatusToleratesUnreadableStats keeps a broken gauge from taking the
// status endpoint down with it.
func TestGetStatusToleratesUnreadableStats(t *testing.T) {
	g := newTestGovernor(failing(errors.New("boom")), failing(errors.New("boom")))
	active, _, _, memPressure, cpuPressure := g.GetStatus(context.Background())
	if !active {
		t.Error("active = false, want true")
	}
	if memPressure != 0 || cpuPressure != 0 {
		t.Errorf("pressure = (%.2f, %.2f), want zeroes when the stats cannot be read", memPressure, cpuPressure)
	}
}

func TestStopIsANoOp(t *testing.T) {
	if err := NewGovernor().Stop(); err != nil {
		t.Errorf("Stop() = %v, want nil", err)
	}
}

// TestLiveUsageFuncsAreWiredByDefault makes sure NewGovernor still reaches the
// real machine. Every other test here replaces both samplers, so without this
// the production wiring would be exercised by nothing at all.
func TestLiveUsageFuncsAreWiredByDefault(t *testing.T) {
	g := NewGovernor()
	if g.memUsage == nil || g.cpuUsage == nil {
		t.Fatal("NewGovernor left a usage function nil")
	}
	if g.interval != defaultInterval {
		t.Errorf("interval = %v, want %v", g.interval, defaultInterval)
	}
	if _, err := g.memUsage(context.Background()); err != nil {
		t.Errorf("live memory sampler failed: %v", err)
	}
}
