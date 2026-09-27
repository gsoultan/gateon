// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package resource

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

// ownCgroupMemory reads this process's cgroup v2 memory.max, memory.current
// and inactive_file directly from the kernel's files. ok is false outside a
// memory-limited cgroup v2.
func ownCgroupMemory(t *testing.T) (limit, current, inactive uint64, ok bool) {
	t.Helper()
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, 0, 0, false
	}
	var dir string
	for line := range strings.SplitSeq(string(self), "\n") {
		if path, found := strings.CutPrefix(line, "0::"); found {
			dir = filepath.Join("/sys/fs/cgroup", path)
		}
	}
	num := func(name string) (uint64, bool) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return 0, false
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return n, err == nil
	}
	limit, limited := num("memory.max")
	current, readable := num("memory.current")
	if dir == "" || !limited || !readable {
		return 0, 0, 0, false
	}
	stat, _ := os.ReadFile(filepath.Join(dir, "memory.stat"))
	for line := range strings.SplitSeq(string(stat), "\n") {
		if v, found := strings.CutPrefix(line, "inactive_file "); found {
			inactive, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	return limit, current, inactive, true
}

// TestTheLiveGaugeMeasuresTheCgroupLimit runs NewGovernor's own gauge inside
// a memory-limited cgroup (a container with --memory, or a unit with
// MemoryMax=) and no Go memory limit. It read host RAM used% there, which in a
// small container on a large host said nothing about the container.
//
// It needs such a cgroup and skips without one: podman run --memory 256m ...
func TestTheLiveGaugeMeasuresTheCgroupLimit(t *testing.T) {
	if _, _, _, ok := ownCgroupMemory(t); !ok {
		t.Skip("not in a memory-limited cgroup v2 (run under podman/docker --memory)")
	}
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	debug.SetMemoryLimit(math.MaxInt64) // no Go limit, so the cgroup decides

	limit, current, inactive, _ := ownCgroupMemory(t)
	used, yardstick, err := NewGovernor().memUsage(context.Background())
	if err != nil {
		t.Fatalf("memUsage: %v", err)
	}
	want := float64(current-min(inactive, current)) / float64(limit) * 100
	if !strings.HasPrefix(yardstick, "cgroup memory.max ") {
		t.Errorf("yardstick = %q, want the cgroup's memory.max", yardstick)
	}
	if math.Abs(used-want) > 5 {
		t.Errorf("memory in use = %.1f%%, want about %.1f%% of the cgroup's %d-byte limit", used, want, limit)
	}
}
