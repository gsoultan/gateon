// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"testing"
)

// BenchmarkIsIPMitigatedByFamily is the answer nearly every request gets --
// not shunned, from the cache -- for an IPv4 and an IPv6 client. Since ADR
// 0058 an IPv6 client is keyed by its /64, which the cache key costs a parse.
func BenchmarkIsIPMitigatedByFamily(b *testing.B) {
	ClosePathStatsStore(context.Background())
	if err := InitPathStatsStore(filepath.Join(b.TempDir(), "bench.db"), 1); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { ClosePathStatsStore(context.Background()) })
	for _, c := range []struct{ name, ip string }{
		{"ipv4", "198.51.100.90"},
		{"ipv6", "2001:db8:1:2:3:4:5:6"},
	} {
		b.Run(c.name, func(b *testing.B) {
			if IsIPMitigated(c.ip) {
				b.Fatal("shunned")
			}
			b.ReportAllocs()
			for b.Loop() {
				IsIPMitigated(c.ip)
			}
		})
	}
}
