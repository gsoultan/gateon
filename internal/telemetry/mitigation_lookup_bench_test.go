// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"testing"
)

// BenchmarkIsIPMitigatedNotShunned is the per-request cost of the answer
// nearly every request gets: an address with no shun, answered from the cache.
func BenchmarkIsIPMitigatedNotShunned(b *testing.B) {
	ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(filepath.Join(b.TempDir(), "bench.db"), 1); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ClosePathStatsStore(context.Background()) })
	const ip = "198.51.100.90"
	if IsIPMitigated(ip) {
		b.Fatal("shunned")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		IsIPMitigated(ip)
	}
}
