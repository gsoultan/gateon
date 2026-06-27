package main

import (
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/gsoultan/gateon/internal/logger"
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
// work harder to stay under the ceiling instead of being OOM-killed. It is
// opt-in: set it too low and the GC can thrash, so we leave it unset by default.
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
	}

	logger.L.LogInfo("runtime tuned",
		"gomaxprocs", runtime.GOMAXPROCS(0),
		"num_cpu", runtime.NumCPU(),
		"gomemlimit_bytes", debug.SetMemoryLimit(-1),
		"gogc_env", os.Getenv("GOGC"),
	)
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
