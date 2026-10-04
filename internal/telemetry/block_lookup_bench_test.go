// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry/repid"
	"github.com/gsoultan/gateon/internal/testutil"
)

// blockLookupBackends is the databases the block lookup benchmarks run on:
// SQLite always, Postgres when GATEON_TEST_POSTGRES_DSN names one.
func blockLookupBackends(b *testing.B, run func(b *testing.B)) {
	b.Run("sqlite", func(b *testing.B) {
		openBenchStore(b, filepath.Join(b.TempDir(), "bench.db"))
		run(b)
	})
	b.Run("postgres", func(b *testing.B) {
		openBenchStore(b, testutil.PostgresDSN(b, "the Postgres block lookup benchmark needs a server"))
		run(b)
	})
}

func openBenchStore(b *testing.B, url string) {
	b.Helper()
	b.Setenv("GATEON_TRACE_DIR", filepath.Join(b.TempDir(), "traces"))
	ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(url, 1); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ClosePathStatsStore(context.Background()) })
}

// BenchmarkIsIPMitigatedUncached is an address the cache has no answer for:
// a new client, once. It is the path that reads the database.
func BenchmarkIsIPMitigatedUncached(b *testing.B) {
	blockLookupBackends(b, func(b *testing.B) {
		const ip = "198.51.100.91"
		s := getStore()
		b.ReportAllocs()
		for b.Loop() {
			s.unmitigatedCache.Remove(ip)
			if IsIPMitigated(ip) {
				b.Fatal("shunned")
			}
		}
	})
}

// BenchmarkIsUserMitigatedCachedBlock is every request a blocked fingerprint
// makes after its first: dataplane F7 read the database for each.
func BenchmarkIsUserMitigatedCachedBlock(b *testing.B) {
	blockLookupBackends(b, func(b *testing.B) {
		key := repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "198.51.100.92")
		MarkUserMitigated(key, "JA4+", "bench", "waf")
		if !IsUserMitigated(key) {
			b.Fatal("not blocked")
		}
		b.ReportAllocs()
		for b.Loop() {
			IsUserMitigated(key)
		}
	})
}

// BenchmarkIsUserMitigatedUncached is a fingerprint key the cache has no
// answer for.
func BenchmarkIsUserMitigatedUncached(b *testing.B) {
	blockLookupBackends(b, func(b *testing.B) {
		key := repid.For("t13d1516h2_8daaf6152771_b0da82dd1658", "192.0.2.93")
		s := getStore()
		b.ReportAllocs()
		for b.Loop() {
			s.userMitigationCache.Remove(key)
			if IsUserMitigated(key) {
				b.Fatal("blocked")
			}
		}
	})
}
