// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package resource

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
)

const mib = 1 << 20

// budget builds a memoryBudget from fixed readings, so which yardstick wins
// is decided by the test and not by the machine running it.
func budget(goLimit int64, goInUse uint64, cgroupInUse, cgroupLimit uint64, cgroupLimited bool, host float64) memoryBudget {
	return memoryBudget{
		goLimit: func() int64 { return goLimit },
		goInUse: func() uint64 { return goInUse },
		cgroup:  func() (uint64, uint64, bool) { return cgroupInUse, cgroupLimit, cgroupLimited },
		host:    fixed(host),
	}
}

func TestMemoryIsMeasuredAgainstTheGoMemoryLimitFirst(t *testing.T) {
	b := budget(512*mib, 480*mib, 100*mib, 1024*mib, true, 10)
	used, yardstick, err := b.usage(context.Background())
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if used != 93.75 || yardstick != "Go memory limit 512 MiB" {
		t.Fatalf("usage = %.2f%% of %q, want 93.75%% of %q: with a Go memory limit set, the "+
			"runtime's own memory against that limit is the budget", used, yardstick, "Go memory limit 512 MiB")
	}
}

func TestMemoryIsMeasuredAgainstTheCgroupWithoutAGoLimit(t *testing.T) {
	b := budget(math.MaxInt64, 480*mib, 900*mib, 1024*mib, true, 10)
	used, yardstick, err := b.usage(context.Background())
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if math.Abs(used-87.890625) > 1e-9 || yardstick != "cgroup memory.max 1 GiB" {
		t.Fatalf("usage = %.4f%% of %q, want 87.8906%% of %q", used, yardstick, "cgroup memory.max 1 GiB")
	}
}

func TestMemoryIsMeasuredAgainstTheHostWithNeitherLimit(t *testing.T) {
	b := budget(math.MaxInt64, 480*mib, 0, 0, false, 42.5)
	used, yardstick, err := b.usage(context.Background())
	if err != nil || used != 42.5 || yardstick != "host memory" {
		t.Fatalf("usage = %.2f%% of %q (%v), want 42.5%% of %q", used, yardstick, err, "host memory")
	}
}

// TestTheGovernorScavengesAtItsLimitWhileTheHostIsIdle is the case the host
// yardstick got wrong: a gateway at 94% of its own limit on a host at 10%. It
// never scavenged, and the next thing to act was the OOM killer.
func TestTheGovernorScavengesAtItsLimitWhileTheHostIsIdle(t *testing.T) {
	g := NewGovernor()
	g.memUsage = budget(512*mib, 480*mib, 0, 0, false, 10).usage
	g.cpuUsage = fixed(0)
	runs := 0
	g.RegisterMemoryHook("proxy_cache", func() { runs++ })

	g.check(context.Background())

	if runs != 1 {
		t.Fatalf("scavengers ran %d times at 94%% of the Go memory limit with the host at 10%%, want 1", runs)
	}
	if got := g.MemoryYardstick(); got != "Go memory limit 512 MiB" {
		t.Errorf("MemoryYardstick() = %q, want the budget the sample was measured against", got)
	}
}

// fakeCgroup writes a cgroup v2 memory controller's files into dir.
func fakeCgroup(t *testing.T, dir, max, current, inactiveFile string) {
	t.Helper()
	for name, content := range map[string]string{
		"memory.max":     max + "\n",
		"memory.current": current + "\n",
		"memory.stat":    "anon 1\nfile 2\ninactive_file " + inactiveFile + "\nactive_file 3\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// TestTheCgroupWorkingSetLeavesOutReclaimableCache: memory.current counts the
// page cache, which the kernel drops before it OOM-kills anything. A gateway
// writing its trace store and logs through that cache reads close to its limit
// for as long as it runs; the working set is what can actually kill it.
func TestTheCgroupWorkingSetLeavesOutReclaimableCache(t *testing.T) {
	dir := t.TempDir()
	fakeCgroup(t, dir, "1073741824", "1000000000", "600000000")

	inUse, limit, ok := cgroupV2{dirs: []string{dir}}.read()
	if !ok || limit != 1073741824 {
		t.Fatalf("read = (%d, %d, %v), want the 1 GiB limit", inUse, limit, ok)
	}
	if inUse != 400000000 {
		t.Fatalf("in use = %d, want memory.current less inactive_file, 400000000", inUse)
	}
}

func TestAnUnlimitedCgroupIsNotAYardstick(t *testing.T) {
	dir := t.TempDir()
	fakeCgroup(t, dir, "max", "1000000000", "0")
	if _, _, ok := (cgroupV2{dirs: []string{dir}}).read(); ok {
		t.Fatal(`memory.max "max" was read as a limit`)
	}
	if _, _, ok := (cgroupV2{dirs: []string{filepath.Join(dir, "absent")}}).read(); ok {
		t.Fatal("a cgroup directory that does not exist was read as a limit")
	}
}

// TestTheCgroupIsFoundFromProcSelfCgroup: the unified hierarchy's line names
// the process's cgroup, under which systemd's MemoryMax= lands; the mount root
// is the fallback for a container sharing the host's cgroup namespace; and
// cgroup v1 has no such line at all.
func TestTheCgroupIsFoundFromProcSelfCgroup(t *testing.T) {
	root := t.TempDir()
	service := filepath.Join(root, "system.slice", "gateon.service")
	if err := os.MkdirAll(service, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeCgroup(t, service, "536870912", "268435456", "0")
	fakeCgroup(t, root, "1073741824", "1073741824", "0")

	cg := cgroupV2FromProc("0::/system.slice/gateon.service\n", root)
	if _, limit, ok := cg.read(); !ok || limit != 536870912 {
		t.Errorf("service cgroup: limit %d (ok %v), want its own 512 MiB", limit, ok)
	}
	cg = cgroupV2FromProc("0::/docker/elsewhere-on-the-host\n", root)
	if _, limit, ok := cg.read(); !ok || limit != 1073741824 {
		t.Errorf("host path not visible: limit %d (ok %v), want the mount root's 1 GiB", limit, ok)
	}
	if cg := cgroupV2FromProc("12:memory:/legacy\n1:name=systemd:/legacy\n", root); len(cg.dirs) != 0 {
		t.Errorf("cgroup v1 produced %v, want nothing to read", cg.dirs)
	}
}

// runtimeInUse reads the runtime's mapped-minus-released memory, the quantity
// a Go memory limit bounds, independently of the code under test.
func runtimeInUse() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

// TestTheLiveGaugeMeasuresTheGoMemoryLimit runs NewGovernor's own gauge in a
// process with a Go memory limit near what it uses. It read host RAM used%,
// whatever the limit said.
func TestTheLiveGaugeMeasuresTheGoMemoryLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	debug.SetMemoryLimit(int64(float64(runtimeInUse()) / 0.92)) // about 92% in use

	used, yardstick, err := NewGovernor().memUsage(context.Background())
	if err != nil {
		t.Fatalf("memUsage: %v", err)
	}
	if !strings.HasPrefix(yardstick, "Go memory limit ") {
		t.Errorf("yardstick = %q, want the Go memory limit the process is running under", yardstick)
	}
	if used < 80 || used > 100 {
		t.Errorf("memory in use = %.1f%%, want about 92%% of the Go memory limit", used)
	}
}

// TestACgroupThatCannotBeReadIsNotAYardstick: a half-readable controller --
// a limit but no usable usage figure -- must not be mistaken for an empty
// cgroup at 0%, which would silence the governor. A missing or garbled
// memory.stat only costs the page-cache adjustment, never the reading.
func TestACgroupThatCannotBeReadIsNotAYardstick(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current string // "" leaves memory.current out
		stat    string // "" leaves memory.stat out
		ok      bool
		inUse   uint64
	}{
		{name: "no memory.current", stat: "inactive_file 1\n"},
		{name: "garbled memory.current", current: "lots\n", stat: "inactive_file 1\n"},
		{name: "no memory.stat", current: "300\n", ok: true, inUse: 300},
		{name: "garbled inactive_file", current: "300\n", stat: "inactive_file many\n", ok: true, inUse: 300},
		{name: "cache larger than usage", current: "300\n", stat: "inactive_file 400\n", ok: true, inUse: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{"memory.max": "1000\n", "memory.current": tc.current, "memory.stat": tc.stat}
			for name, content := range files {
				if content == "" {
					continue
				}
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			inUse, _, ok := cgroupV2{dirs: []string{dir}}.read()
			if ok != tc.ok || inUse != tc.inUse {
				t.Fatalf("read = (%d, ok %v), want (%d, ok %v)", inUse, ok, tc.inUse, tc.ok)
			}
		})
	}
}

func TestLimitsAreNamedInTheUnitsTheyAreSetIn(t *testing.T) {
	for n, want := range map[uint64]string{
		2 << 30:     "2 GiB",
		1536 * mib:  "1536 MiB",
		3 * mib / 2: "1.5 MiB",
		512 << 10:   "524288 B",
	} {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestTheYardstickIsUnknownUntilMeasured: before the first sample there is
// nothing to report, and an empty answer says so rather than guessing.
func TestTheYardstickIsUnknownUntilMeasured(t *testing.T) {
	if got := NewGovernor().MemoryYardstick(); got != "" {
		t.Fatalf("MemoryYardstick() before any sample = %q, want empty", got)
	}
}
