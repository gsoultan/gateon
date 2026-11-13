// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package resource

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/shirou/gopsutil/v3/cpu"
)

// ScavengeHook defines a callback function triggered under resource pressure.
type ScavengeHook func()

// Pressure thresholds, in percent of the resource in use, above which the
// registered scavenge hooks run.
const (
	memoryPressurePercent = 80.0
	cpuPressurePercent    = 90.0
)

// defaultInterval is how often Start samples. Five seconds is frequent enough
// to react to a leak and rare enough that the sampling itself is not a load.
const defaultInterval = 5 * time.Second

// memoryScavengeCooldown is the least time between two runs of the memory
// scavengers within one spell of pressure.
//
// They ran on every sample, and the proxy cache's scavenger discards every
// route's balancer and backend connection pool. Under sustained pressure -- a
// 2 GB host near its ceiling, a busy shared machine -- every request after each
// purge paid for new connections and TLS handshakes, twelve times a minute,
// while a purge that did not relieve the pressure the first time relieved
// nothing the next eleven. A new spell of pressure still scavenges at once.
const memoryScavengeCooldown = time.Minute

// usageFunc reports how much of a resource is in use, as a percentage.
//
// The live samplers are swappable because they are also the reason this
// package used to be untestable: the branches below only run above 80% and
// 90%, so whether they executed depended on how loaded the machine happened to
// be, and coverage of this package swung 17 points between CI runs on one
// commit. Memory is measured by a memoryGauge, which also names its yardstick
// (memory_budget.go).
type usageFunc func(context.Context) (float64, error)

func liveCPUUsage(ctx context.Context) (float64, error) {
	percentages, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return 0, err
	}
	if len(percentages) == 0 {
		return 0, errNoCPUSample
	}
	return percentages[0], nil
}

// errNoCPUSample is returned when gopsutil reports no CPU samples at all,
// which is indistinguishable from an error for our purposes: we cannot say
// whether there is pressure, so we do not act as though there is none.
var errNoCPUSample = errors.New("no cpu samples returned")

// Governor monitors system resources and triggers callbacks to mitigate pressure.
type Governor struct {
	memoryHooks map[string]ScavengeHook
	cpuHooks    map[string]ScavengeHook
	mu          sync.RWMutex
	interval    time.Duration
	memUsage    memoryGauge
	cpuUsage    usageFunc
	now         func() time.Time // injectable for tests

	// yardstick names the budget the last memory sample was measured against.
	yardstick atomic.Pointer[string]

	// lastScavenge is when the memory scavengers last ran in the current spell
	// of pressure, in UnixNano; 0 outside one.
	lastScavenge atomic.Int64

	// running is true while Start's loop is.
	running atomic.Bool
	// What the loop last measured, for Status. Written by the loop only.
	lastMemory, lastCPU atomicPercent
}

// atomicPercent is one reading the loop took: a percentage, or a failure to
// read one.
type atomicPercent struct {
	bits    atomic.Uint64 // math.Float64bits of the percentage
	taken   atomic.Bool   // a reading has been attempted
	failing atomic.Bool   // the last attempt could not read the value
}

func (a *atomicPercent) store(percent float64, err error) {
	a.failing.Store(err != nil)
	if err == nil {
		a.bits.Store(math.Float64bits(percent))
	}
	a.taken.Store(true)
}

func (a *atomicPercent) load() float64 { return math.Float64frombits(a.bits.Load()) }

// NewGovernor creates a new resource governor with default monitoring interval.
func NewGovernor() *Governor {
	return &Governor{
		memoryHooks: make(map[string]ScavengeHook),
		cpuHooks:    make(map[string]ScavengeHook),
		interval:    defaultInterval,
		memUsage:    liveMemoryBudget().usage,
		cpuUsage:    liveCPUUsage,
		now:         time.Now,
	}
}

// RegisterMemoryHook adds a callback to be executed when memory pressure is high (>80%).
func (g *Governor) RegisterMemoryHook(name string, hook ScavengeHook) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.memoryHooks[name] = hook
}

// RegisterCPUHook adds a callback to be executed when CPU pressure is high.
func (g *Governor) RegisterCPUHook(name string, hook ScavengeHook) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cpuHooks[name] = hook
}

// Start begins the resource monitoring loop.
func (g *Governor) Start(ctx context.Context) {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	g.running.Store(true)
	defer g.running.Store(false)
	g.logStart(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.L.LogInfo("resource governor stopped")
			return
		case <-ticker.C:
			g.check(ctx)
		}
	}
}

// logStart says what memory pressure will be measured against, which is the
// first thing to check when the governor purges caches, or does not.
func (g *Governor) logStart(ctx context.Context) {
	used, yardstick, err := g.sampleMemory(ctx)
	if err != nil {
		logger.L.LogWarn("resource governor started, but memory cannot be read",
			"memory_yardstick", yardstick, "error", err)
		return
	}
	logger.L.LogInfo("resource governor started",
		"memory_yardstick", yardstick, "memory_used_percent", used)
}

// Stop manually stops the governor. (Context-based Start usually handles this).
func (g *Governor) Stop() error {
	return nil
}

func (g *Governor) check(ctx context.Context) {
	g.checkMemory(ctx)
	g.checkCPU(ctx)
}

func (g *Governor) checkMemory(ctx context.Context) {
	used, yardstick, err := g.sampleMemory(ctx)
	if err != nil {
		logger.L.LogWarn("governor failed to get memory stats", "error", err)
		return
	}
	if used <= memoryPressurePercent {
		g.lastScavenge.Store(0) // the spell is over
		return
	}
	now := time.Now()
	if g.now != nil {
		now = g.now()
	}
	if last := g.lastScavenge.Load(); last != 0 && now.UnixNano()-last < int64(memoryScavengeCooldown) {
		return
	}
	g.lastScavenge.Store(now.UnixNano())
	logger.L.LogWarn("high memory pressure detected", "used_percent", used, "of", yardstick)
	for name, hook := range g.snapshot(g.memoryHooks) {
		logger.L.LogDebug("triggering memory scavenge hook", "name", name)
		hook()
	}
}

func (g *Governor) checkCPU(ctx context.Context) {
	used, err := g.cpuUsage(ctx)
	g.lastCPU.store(used, err)
	if err != nil {
		return
	}
	if used <= cpuPressurePercent {
		return
	}
	logger.L.LogWarn("high CPU pressure detected", "used_percent", used)
	for name, hook := range g.snapshot(g.cpuHooks) {
		logger.L.LogDebug("triggering CPU scavenge hook", "name", name)
		hook()
	}
}

// snapshot copies a hook set under the read lock so the hooks themselves run
// unlocked. A scavenge hook is arbitrary caller code — it may take its own
// locks, or register another hook — and holding g.mu across it would make the
// governor a deadlock the caller cannot see.
func (g *Governor) snapshot(hooks map[string]ScavengeHook) map[string]ScavengeHook {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]ScavengeHook, len(hooks))
	for k, v := range hooks {
		out[k] = v
	}
	return out
}

// Status is what the governor last measured and whether it is measuring.
type Status struct {
	// Running is true while the monitoring loop runs. The dashboard read
	// "active" from a GetStatus that answered true whether or not the loop had
	// ever started.
	Running bool
	// Sampled is true once both memory and CPU have been read; until then a
	// percentage is a zero nobody measured. Memory is read as the loop starts
	// and CPU on its first tick, so for one interval only memory is known.
	Sampled bool
	// Unreadable is true when the last memory or CPU reading failed. The
	// percentages then read 0, which is not "no pressure".
	Unreadable bool

	MemoryHooks, CPUHooks int

	MemoryPercent, CPUPercent float64
	// MemoryThreshold and CPUThreshold are the percentages above which the
	// hooks run.
	MemoryThreshold, CPUThreshold float64
	// MemoryYardstick names the budget MemoryPercent is measured against.
	MemoryYardstick string
}

// UnderPressure reports whether the last readings were above a threshold, the
// condition in which the governor runs its hooks.
func (s Status) UnderPressure() bool {
	return s.MemoryPercent > s.MemoryThreshold || s.CPUPercent > s.CPUThreshold
}

// Status reports what the loop last measured. It does not sample: a CPU
// reading is the usage since the previous one, process-wide, so a status
// request that took its own would shorten the loop's next window to however
// long ago the dashboard last asked.
func (g *Governor) Status() Status {
	g.mu.RLock()
	memHooks, cpuHooks := len(g.memoryHooks), len(g.cpuHooks)
	g.mu.RUnlock()
	return Status{
		Running:         g.running.Load(),
		Sampled:         g.lastMemory.taken.Load() && g.lastCPU.taken.Load(),
		Unreadable:      g.lastMemory.failing.Load() || g.lastCPU.failing.Load(),
		MemoryHooks:     memHooks,
		CPUHooks:        cpuHooks,
		MemoryPercent:   g.lastMemory.load(),
		CPUPercent:      g.lastCPU.load(),
		MemoryThreshold: memoryPressurePercent,
		CPUThreshold:    cpuPressurePercent,
		MemoryYardstick: g.MemoryYardstick(),
	}
}

// sampleMemory takes one memory sample and remembers what it was measured
// against.
func (g *Governor) sampleMemory(ctx context.Context) (float64, string, error) {
	used, yardstick, err := g.memUsage(ctx)
	g.yardstick.Store(&yardstick)
	g.lastMemory.store(used, err)
	return used, yardstick, err
}

// MemoryYardstick names the budget memory pressure was last measured against:
// the Go memory limit, the cgroup's memory.max, or the host's memory. Empty
// until the first sample.
func (g *Governor) MemoryYardstick() string {
	if y := g.yardstick.Load(); y != nil {
		return *y
	}
	return ""
}
