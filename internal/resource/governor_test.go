// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package resource

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestGovernor_Hooks(t *testing.T) {
	g := NewGovernor()
	g.interval = 50 * time.Millisecond

	var memCalled atomic.Bool
	var cpuCalled atomic.Bool

	g.RegisterMemoryHook("test_mem", func() {
		memCalled.Store(true)
	})
	g.RegisterCPUHook("test_cpu", func() {
		cpuCalled.Store(true)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go g.Start(ctx)

	// Since we can't easily force high CPU/Memory in a portable unit test without
	// heavy dependencies or unsafe tricks, we manually trigger the check with
	// mocks if needed. But here we just verify the registry works.

	g.mu.RLock()
	memLen := len(g.memoryHooks)
	cpuLen := len(g.cpuHooks)
	g.mu.RUnlock()

	if memLen != 1 {
		t.Errorf("Expected 1 memory hook, got %d", memLen)
	}
	if cpuLen != 1 {
		t.Errorf("Expected 1 CPU hook, got %d", cpuLen)
	}

	// Wait for one tick
	time.Sleep(100 * time.Millisecond)

	// GetStatus should work
	active, mh, ch, _, _ := g.GetStatus(ctx)
	if !active || mh != 1 || ch != 1 {
		t.Errorf("GetStatus failed: active=%v, memHooks=%d, cpuHooks=%d", active, mh, ch)
	}
}
