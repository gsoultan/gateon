// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"testing"
	"time"
)

func TestNormalizeTier(t *testing.T) {
	cases := map[string]Tier{
		"minimal":    TierMinimal,
		"MINIMAL":    TierMinimal,
		" Standard ": TierStandard,
		"enterprise": TierEnterprise,
		"":           TierStandard,
		"bogus":      TierStandard,
	}
	for in, want := range cases {
		if got := NormalizeTier(in); got != want {
			t.Errorf("NormalizeTier(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveProfile_EnvWins(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "enterprise")
	if got := ResolveProfile(); got != TierEnterprise {
		t.Fatalf("ResolveProfile() = %q, want enterprise", got)
	}
}

func TestResolveProfile_DefaultStandard(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "")
	// No global config registered in this unit context => standard.
	if got := ResolveProfile(); got != TierStandard {
		t.Fatalf("ResolveProfile() = %q, want standard", got)
	}
}

func TestDefaultsFor_ConservativeMinimal(t *testing.T) {
	min := DefaultsFor(TierMinimal)
	std := DefaultsFor(TierStandard)
	ent := DefaultsFor(TierEnterprise)

	if min.TraceStoreEnabled {
		t.Error("minimal tier should not enable the trace store by default")
	}
	if !std.TraceStoreEnabled || !ent.TraceStoreEnabled {
		t.Error("standard/enterprise should enable the trace store")
	}
	// Footprint must be monotonic across tiers for the key bounds.
	if min.CorrelationMaxSources > std.CorrelationMaxSources || std.CorrelationMaxSources > ent.CorrelationMaxSources {
		t.Error("CorrelationMaxSources must be non-decreasing minimal<=standard<=enterprise")
	}
	if min.PebbleCacheBytes > std.PebbleCacheBytes || std.PebbleCacheBytes > ent.PebbleCacheBytes {
		t.Error("PebbleCacheBytes must be non-decreasing minimal<=standard<=enterprise")
	}
	if min.RetentionDays > std.RetentionDays || std.RetentionDays > ent.RetentionDays {
		t.Error("RetentionDays must be non-decreasing minimal<=standard<=enterprise")
	}
	// A TCP entrypoint with max_connections 0 takes this; 0 here would be no cap.
	if min.EntryPointMaxConnections <= 0 || min.EntryPointMaxConnections > std.EntryPointMaxConnections ||
		std.EntryPointMaxConnections > ent.EntryPointMaxConnections {
		t.Error("EntryPointMaxConnections must be positive and non-decreasing minimal<=standard<=enterprise")
	}
	// The per-address cap must be positive (0 would be no per-address cap),
	// non-decreasing across tiers, and never looser than the entrypoint-wide
	// cap it complements -- one address may not be allowed more than the whole
	// entrypoint holds.
	if min.EntryPointMaxConnPerAddr <= 0 || min.EntryPointMaxConnPerAddr > std.EntryPointMaxConnPerAddr ||
		std.EntryPointMaxConnPerAddr > ent.EntryPointMaxConnPerAddr {
		t.Error("EntryPointMaxConnPerAddr must be positive and non-decreasing minimal<=standard<=enterprise")
	}
	if min.EntryPointMaxConnPerAddr > min.EntryPointMaxConnections ||
		ent.EntryPointMaxConnPerAddr > ent.EntryPointMaxConnections {
		t.Error("EntryPointMaxConnPerAddr must not exceed EntryPointMaxConnections")
	}
}

// TestHeaderBufferingFitsEachTiersMemory is ADR 0042's arithmetic: every
// connection an entrypoint admits may be one still sending its header, and
// the Go memory such a connection holds was measured at up to 1.7 times the
// header cap plus 4 KiB (52.6 KiB at 32 KiB). A tier's connection cap filled
// that way has to fit in half of the memory the tier is sized for -- minimal
// a 512 MiB host, standard the 2 GB target's 1536 MiB runtime limit,
// enterprise a 16 GiB host. The cap was 1 MiB: 10 GiB on standard.
func TestHeaderBufferingFitsEachTiersMemory(t *testing.T) {
	budgets := map[Tier]int64{TierMinimal: 256 << 20, TierStandard: 768 << 20, TierEnterprise: 8 << 30}
	for tier, budget := range budgets {
		d := DefaultsFor(tier)
		if d.MaxHeaderBytes < 16<<10 {
			t.Errorf("%s: MaxHeaderBytes %d is under 16 KiB, which ordinary browsers' cookies exceed", tier, d.MaxHeaderBytes)
		}
		perConn := int64(d.MaxHeaderBytes)*17/10 + 4<<10
		if worst := int64(d.EntryPointMaxConnections) * perConn; worst > budget {
			t.Errorf("%s: %d connections x %d bytes = %d MiB of header buffering, over its %d MiB budget",
				tier, d.EntryPointMaxConnections, perConn, worst>>20, budget>>20)
		}
	}
}

// TestStreamBoundsAreSetOnEveryTier: a stream lifted off its request's
// deadlines must still have both bounds, and its lifetime must be longer than
// its idle timeout or the idle timeout would never be what ends it.
func TestStreamBoundsAreSetOnEveryTier(t *testing.T) {
	for _, tier := range []Tier{TierMinimal, TierStandard, TierEnterprise} {
		d := DefaultsFor(tier)
		if d.StreamIdleTimeout <= 0 || d.StreamMaxLifetime <= d.StreamIdleTimeout {
			t.Errorf("%s: idle %v, lifetime %v; want both set, lifetime the longer", tier, d.StreamIdleTimeout, d.StreamMaxLifetime)
		}
	}
}

// Every tier gives a block lookup a deadline short enough that a database that
// stopped answering costs a new client a fraction of a second, not as long as
// the database stays stopped (ADR 0054). Zero would be no deadline at all.
func TestBlockLookupsHaveADeadlineOnEveryTier(t *testing.T) {
	for _, tier := range []Tier{TierMinimal, TierStandard, TierEnterprise} {
		if d := DefaultsFor(tier).BlockLookupTimeout; d <= 0 || d > time.Second {
			t.Errorf("%s: block lookup deadline %v; want set, and under a second", tier, d)
		}
	}
}
