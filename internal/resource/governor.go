// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package resource

import (
	"context"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// ScavengeHook defines a callback function triggered under resource pressure.
type ScavengeHook func()

// Governor monitors system resources and triggers callbacks to mitigate pressure.
type Governor struct {
	memoryHooks map[string]ScavengeHook
	cpuHooks    map[string]ScavengeHook
	mu          sync.RWMutex
	interval    time.Duration
}

// NewGovernor creates a new resource governor with default monitoring interval.
func NewGovernor() *Governor {
	return &Governor{
		memoryHooks: make(map[string]ScavengeHook),
		cpuHooks:    make(map[string]ScavengeHook),
		interval:    5 * time.Second,
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

	logger.L.LogInfo("resource governor started")

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

// Stop manually stops the governor. (Context-based Start usually handles this).
func (g *Governor) Stop() error {
	return nil
}

func (g *Governor) check(ctx context.Context) {
	g.checkMemory(ctx)
	g.checkCPU(ctx)
}

func (g *Governor) checkMemory(ctx context.Context) {
	v, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		logger.L.LogWarn("governor failed to get memory stats", "error", err)
		return
	}

	if v.UsedPercent > 80 {
		logger.L.LogWarn("high memory pressure detected", "used_percent", v.UsedPercent)
		g.mu.RLock()
		hooks := g.memoryHooks
		g.mu.RUnlock()

		for name, hook := range hooks {
			logger.L.LogDebug("triggering memory scavenge hook", "name", name)
			hook()
		}
	}
}

func (g *Governor) checkCPU(ctx context.Context) {
	percentages, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil || len(percentages) == 0 {
		return
	}

	if percentages[0] > 90 {
		logger.L.LogWarn("high CPU pressure detected", "used_percent", percentages[0])
		g.mu.RLock()
		hooks := g.cpuHooks
		g.mu.RUnlock()

		for name, hook := range hooks {
			logger.L.LogDebug("triggering CPU scavenge hook", "name", name)
			hook()
		}
	}
}

// GetStatus returns the current stats of the resource governor.
func (g *Governor) GetStatus(ctx context.Context) (active bool, memHooks, cpuHooks int, memPressure, cpuPressure float64) {
	g.mu.RLock()
	memHooks = len(g.memoryHooks)
	cpuHooks = len(g.cpuHooks)
	g.mu.RUnlock()

	active = true
	v, _ := mem.VirtualMemoryWithContext(ctx)
	if v != nil {
		memPressure = v.UsedPercent
	}
	percentages, _ := cpu.PercentWithContext(ctx, 0, false)
	if len(percentages) > 0 {
		cpuPressure = percentages[0]
	}
	return
}
