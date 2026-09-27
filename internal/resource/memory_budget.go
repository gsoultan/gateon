// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package resource

import (
	"context"
	"math"
	"os"
	"path"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v3/mem"
)

// memoryGauge reports memory in use as a percentage of a budget, and names the
// budget it measured against.
type memoryGauge func(context.Context) (percent float64, yardstick string, err error)

// memoryBudget measures memory pressure against the memory the process may
// actually use. The first reader that reports a limit decides:
//
//  1. a Go memory limit -- GOMEMLIMIT, or GATEON_MEMORY_LIMIT applied through
//     debug.SetMemoryLimit -- against the runtime memory that limit bounds;
//  2. the process's cgroup v2 memory.max, against the cgroup's working set;
//  3. the host's RAM, which was the only yardstick.
//
// Host RAM is the wrong one wherever a limit exists. In a 512 MiB container on
// a 16 GiB node the gateway reached its OOM line with the host at 20% and
// never scavenged; on a shared 2 GB host, other processes' memory set off
// purges of the gateway's own caches.
type memoryBudget struct {
	goLimit func() int64  // the Go memory limit; math.MaxInt64 when unset
	goInUse func() uint64 // runtime memory the Go limit bounds
	cgroup  func() (inUse, limit uint64, ok bool)
	host    usageFunc
}

// usage implements memoryGauge.
func (b memoryBudget) usage(ctx context.Context) (float64, string, error) {
	if limit := b.goLimit(); limit > 0 && limit < math.MaxInt64 {
		return percentOf(b.goInUse(), uint64(limit)), "Go memory limit " + formatBytes(uint64(limit)), nil
	}
	if inUse, limit, ok := b.cgroup(); ok {
		return percentOf(inUse, limit), "cgroup memory.max " + formatBytes(limit), nil
	}
	p, err := b.host(ctx)
	return p, "host memory", err
}

func percentOf(inUse, limit uint64) float64 {
	return float64(inUse) / float64(limit) * 100
}

// formatBytes renders a limit in the binary units operators configure it in.
func formatBytes(n uint64) string {
	switch {
	case n >= 1<<30 && n%(1<<30) == 0:
		return strconv.FormatUint(n>>30, 10) + " GiB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', -1, 64) + " MiB"
	default:
		return strconv.FormatUint(n, 10) + " B"
	}
}

// liveMemoryBudget reads this process, its cgroup and the host.
func liveMemoryBudget() memoryBudget {
	cg := cgroupV2{}
	if self, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		cg = cgroupV2FromProc(string(self), "/sys/fs/cgroup")
	}
	return memoryBudget{
		goLimit: func() int64 { return debug.SetMemoryLimit(-1) },
		goInUse: goRuntimeInUse,
		cgroup:  cg.read,
		host:    hostMemoryUsage,
	}
}

// goRuntimeInUse is the memory the Go memory limit is enforced against: all
// memory the runtime has mapped, less what it has returned to the OS.
func goRuntimeInUse() uint64 {
	s := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(s)
	return saturatingSub(s[0].Value.Uint64(), s[1].Value.Uint64())
}

func hostMemoryUsage(ctx context.Context) (float64, error) {
	v, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return 0, err
	}
	return v.UsedPercent, nil
}

// cgroupV2 reads the memory controller of the process's cgroup v2.
//
// Every read goes through an os.Root opened at the cgroup2 mount, and dirs are
// relative to it: the path comes from /proc/self/cgroup, and os.Root refuses
// any name -- a ".." or a symlink inside the mount -- that would resolve to a
// file elsewhere on the host.
type cgroupV2 struct {
	root string   // the cgroup2 mount
	dirs []string // where to look under root, in order; "." is the mount itself
}

// cgroupV2FromProc finds the process's cgroup from the contents of
// /proc/self/cgroup, whose unified-hierarchy line reads "0::<path>", under the
// cgroup2 mount at root. The mount root itself is the second place to look: a
// container that shares the host's cgroup namespace sees its full host path
// there, while its own cgroup is what is mounted at root.
func cgroupV2FromProc(procSelfCgroup, root string) cgroupV2 {
	for line := range strings.SplitSeq(procSelfCgroup, "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			rel := strings.TrimPrefix(path.Clean("/"+p), "/")
			if rel == "" {
				return cgroupV2{root: root, dirs: []string{"."}}
			}
			return cgroupV2{root: root, dirs: []string{rel, "."}}
		}
	}
	return cgroupV2{} // cgroup v1, or none: no limit this can read
}

// read reports the cgroup's working set and its memory.max. ok is false when
// there is no limit or it cannot be read.
//
// The working set is memory.current less inactive_file, the page cache the
// kernel reclaims before it would OOM-kill anything, as the kubelet counts it.
// memory.current alone includes that cache, and a gateway that writes its
// trace store and logs through the page cache would read close to 100% of its
// limit for as long as it ran.
func (c cgroupV2) read() (inUse, limit uint64, ok bool) {
	if c.root == "" || len(c.dirs) == 0 {
		return 0, 0, false
	}
	r, err := os.OpenRoot(c.root)
	if err != nil {
		return 0, 0, false
	}
	defer func() { _ = r.Close() }()
	for _, dir := range c.dirs {
		if inUse, limit, ok = readCgroupMemory(r, dir); ok {
			return inUse, limit, true
		}
	}
	return 0, 0, false
}

func readCgroupMemory(r *os.Root, dir string) (inUse, limit uint64, ok bool) {
	raw, err := r.ReadFile(path.Join(dir, "memory.max"))
	if err != nil {
		return 0, 0, false
	}
	limit, err = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || limit == 0 { // "max" is no limit
		return 0, 0, false
	}
	raw, err = r.ReadFile(path.Join(dir, "memory.current"))
	if err != nil {
		return 0, 0, false
	}
	current, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return saturatingSub(current, inactiveFile(r, dir)), limit, true
}

// inactiveFile is memory.stat's inactive_file, or 0 when it cannot be read.
func inactiveFile(r *os.Root, dir string) uint64 {
	raw, err := r.ReadFile(path.Join(dir, "memory.stat"))
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		if v, found := strings.CutPrefix(line, "inactive_file "); found {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
