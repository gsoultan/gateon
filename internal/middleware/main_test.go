// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"flag"
	"log/slog"
	"os"
	"testing"
)

// TestMain silences the default slog logger while benchmarks run.
//
// `go test` hands the test binary a single stream for stdout and stderr and
// reprints all of it on its own stdout, so anything logged during a benchmark
// lands *inside* the result row:
//
//	BenchmarkWAFRequestWithInboundDLP-15   2026/09/04 INFO gwaf: a rule cannot...
//
// benchstat cannot parse that row and drops it silently. That is why
// doc/benchmarks/README.md had no WAF entries at all: the four WAF benchmarks
// have existed and run green this whole time, and every one of their results
// was discarded before it reached the baseline. A benchmark whose output never
// arrives is indistinguishable from one nobody wrote.
//
// The noise is gwaf's rule diagnostics, emitted once per engine build. gwaf
// defaults to slog.Default() (gwaf@v0.6.0 options.go:150) and gateon points
// that at its own configured handler in production (internal/logger,
// slog.SetDefault), so this is a harness problem and not a production one —
// hence a discard here rather than any change to how the engine is built.
//
// Gated on -test.bench so `go test` keeps its logs: they are useful when a test
// fails, and a failing benchmark is not a thing that happens. flag.Parse runs
// first because M.Run is what would otherwise parse them, and the flag has to
// be readable before that.
func TestMain(m *testing.M) {
	flag.Parse()
	if f := flag.Lookup("test.bench"); f != nil && f.Value.String() != "" {
		slog.SetDefault(slog.New(slog.DiscardHandler))
	}
	os.Exit(m.Run())
}
