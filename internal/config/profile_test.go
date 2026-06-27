package config

import "testing"

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
	if !(min.CorrelationMaxSources <= std.CorrelationMaxSources && std.CorrelationMaxSources <= ent.CorrelationMaxSources) {
		t.Error("CorrelationMaxSources must be non-decreasing minimal<=standard<=enterprise")
	}
	if !(min.PebbleCacheBytes <= std.PebbleCacheBytes && std.PebbleCacheBytes <= ent.PebbleCacheBytes) {
		t.Error("PebbleCacheBytes must be non-decreasing minimal<=standard<=enterprise")
	}
	if !(min.RetentionDays <= std.RetentionDays && std.RetentionDays <= ent.RetentionDays) {
		t.Error("RetentionDays must be non-decreasing minimal<=standard<=enterprise")
	}
}
