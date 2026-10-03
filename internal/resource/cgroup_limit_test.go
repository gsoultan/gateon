// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package resource

import (
	"os"
	"testing"
)

// TestCgroupMemoryLimitIsTheBudgetsLimit: the limit the runtime derives its Go
// soft limit from is the one the governor measures against.
func TestCgroupMemoryLimitIsTheBudgetsLimit(t *testing.T) {
	limit, ok := CgroupMemoryLimit()
	var want uint64
	var wantOK bool
	if self, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		_, want, wantOK = cgroupV2FromProc(string(self), "/sys/fs/cgroup").read()
	}
	if limit != want || ok != wantOK {
		t.Errorf("CgroupMemoryLimit() = %d, %v; the budget reads %d, %v", limit, ok, want, wantOK)
	}
}
