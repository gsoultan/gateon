// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/resource"
)

// tuneRuntime applies container-aware runtime settings for a low-footprint,
// predictable gateway and logs the effective values for observability.
//
// GOMAXPROCS: Go 1.25+ already sets the default from the cgroup CPU bandwidth
// limit on Linux, so a containerized gateon no longer over-subscribes the host's
// core count (which caused scheduler churn, excess GC assists, and CPU
// throttling). We do not override it here; we only surface the effective value.
//
// Memory: Go natively honors the GOMEMLIMIT env var. For convenience we also
// accept GATEON_MEMORY_LIMIT (e.g. "512MiB", "1GiB", or a raw byte count) and
// apply it as a soft limit via debug.SetMemoryLimit. A soft limit makes the GC
// work harder to stay under the ceiling instead of being OOM-killed. With
// neither set, and a cgroup memory limit in force -- the packaged unit's
// MemoryMax, a container's --memory -- the soft limit is derived from it
// (cgroupMemoryLimitShare). Without that the GC did not know the ceiling was
// there until the kernel OOM-killed the process at it.
//
// GC target: GATEON_GOGC overrides the GC percentage (lower = less memory, more
// CPU; higher = more memory, less CPU). Go also honors the GOGC env var natively;
// this is the same knob exposed explicitly.
func tuneRuntime() {
	if v := strings.TrimSpace(os.Getenv("GATEON_GOGC")); v != "" {
		if pct, err := strconv.Atoi(v); err == nil {
			debug.SetGCPercent(pct)
		} else {
			logger.L.LogWarn("invalid GATEON_GOGC, ignoring", "value", v)
		}
	}

	if v := strings.TrimSpace(os.Getenv("GATEON_MEMORY_LIMIT")); v != "" {
		if limit, err := parseByteSize(v); err == nil && limit > 0 {
			debug.SetMemoryLimit(limit)
		} else {
			logger.L.LogWarn("invalid GATEON_MEMORY_LIMIT, ignoring", "value", v)
		}
	} else if limit, ok := derivedMemoryLimit(os.Getenv, resource.CgroupMemoryLimit); ok {
		debug.SetMemoryLimit(limit)
		logger.L.LogInfo("Go memory limit derived from the cgroup memory limit; set GATEON_MEMORY_LIMIT to choose it",
			"gomemlimit_bytes", limit)
	}

	logger.L.LogInfo("runtime tuned",
		"gomaxprocs", runtime.GOMAXPROCS(0),
		"num_cpu", runtime.NumCPU(),
		"gomemlimit_bytes", debug.SetMemoryLimit(-1),
		"gogc_env", os.Getenv("GOGC"),
	)
}

// cgroupMemoryLimitShare is the share of a cgroup memory limit the derived Go
// soft limit takes: the rest is the stacks, the allocator's metadata and what
// is mapped outside the heap, which the cgroup counts and GOMEMLIMIT does not.
// Under the packaged unit's MemoryMax=90% on the 2 GB target it gives ~1.5 GiB,
// what doc/deployment-sizing.md recommends.
const cgroupMemoryLimitShare = 85

// derivedMemoryLimit is the soft limit to apply when the operator set none:
// cgroupMemoryLimitShare percent of the cgroup's memory.max, and false when
// GOMEMLIMIT is set (the runtime already applied it) or there is no limit.
func derivedMemoryLimit(getenv func(string) string, cgroupLimit func() (uint64, bool)) (int64, bool) {
	if strings.TrimSpace(getenv("GOMEMLIMIT")) != "" {
		return 0, false
	}
	limit, ok := cgroupLimit()
	if !ok || limit == 0 || limit > math.MaxInt64 {
		return 0, false
	}
	return int64(limit / 100 * cgroupMemoryLimitShare), true
}

// parseByteSize parses a byte count with an optional binary (Ki/Mi/Gi/Ti) or
// decimal (K/M/G/T, also B) suffix. A bare number is treated as bytes.
func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, "KIB"):
		mult, s = 1<<10, s[:len(s)-3]
	case strings.HasSuffix(upper, "MIB"):
		mult, s = 1<<20, s[:len(s)-3]
	case strings.HasSuffix(upper, "GIB"):
		mult, s = 1<<30, s[:len(s)-3]
	case strings.HasSuffix(upper, "TIB"):
		mult, s = 1<<40, s[:len(s)-3]
	case strings.HasSuffix(upper, "KB"), strings.HasSuffix(upper, "K"):
		mult, s = 1_000, trimSuffixUpper(s, upper, "KB", "K")
	case strings.HasSuffix(upper, "MB"), strings.HasSuffix(upper, "M"):
		mult, s = 1_000_000, trimSuffixUpper(s, upper, "MB", "M")
	case strings.HasSuffix(upper, "GB"), strings.HasSuffix(upper, "G"):
		mult, s = 1_000_000_000, trimSuffixUpper(s, upper, "GB", "G")
	case strings.HasSuffix(upper, "TB"), strings.HasSuffix(upper, "T"):
		mult, s = 1_000_000_000_000, trimSuffixUpper(s, upper, "TB", "T")
	case strings.HasSuffix(upper, "B"):
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}

func trimSuffixUpper(s, upper, two, one string) string {
	if strings.HasSuffix(upper, two) {
		return s[:len(s)-len(two)]
	}
	return s[:len(s)-len(one)]
}
