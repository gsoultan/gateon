// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import "testing"

// TestTheGoMemoryLimitFollowsTheCgroupLimitWhenNoneIsSet: the packaged unit
// sets nothing the Go runtime reads, so with a cgroup ceiling and no
// GOMEMLIMIT the GC did not know the ceiling was there until the kernel
// OOM-killed the process at it (review F8: gomemlimit_bytes=9223372036854775807
// at startup). The derived limit is 85% of memory.max; an operator's
// GOMEMLIMIT, or no cgroup limit, leaves the runtime alone.
func TestTheGoMemoryLimitFollowsTheCgroupLimitWhenNoneIsSet(t *testing.T) {
	const gib = 1 << 30
	limitOf := func(n uint64, ok bool) func() (uint64, bool) { return func() (uint64, bool) { return n, ok } }
	env := func(gomemlimit string) func(string) string {
		return func(k string) string {
			if k == "GOMEMLIMIT" {
				return gomemlimit
			}
			return ""
		}
	}

	// MemoryMax=90% of the 2 GB target.
	got, ok := derivedMemoryLimit(env(""), limitOf(1843*1<<20, true))
	if !ok || got < 1500<<20 || got > 1600<<20 {
		t.Errorf("derived limit under a 1843 MiB cgroup = %d MiB (ok=%v), want about 1536 MiB", got>>20, ok)
	}
	if _, ok := derivedMemoryLimit(env("1GiB"), limitOf(2*gib, true)); ok {
		t.Error("a GOMEMLIMIT the operator set was overridden")
	}
	if _, ok := derivedMemoryLimit(env(""), limitOf(0, false)); ok {
		t.Error("a limit was derived with no cgroup limit")
	}
	if _, ok := derivedMemoryLimit(env(""), limitOf(1<<63+1, true)); ok {
		t.Error("a limit past int64 was derived")
	}
}
