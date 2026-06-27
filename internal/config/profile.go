package config

import (
	"os"
	"strings"
)

// Tier is a resource profile preset. It sizes heavy subsystems (correlation
// engine, telemetry sketches, trace store, retention, Pebble, WAF) for the
// deployment's footprint without removing capabilities — every subsystem stays
// configurable; the tier only supplies conservative defaults.
type Tier string

const (
	// TierMinimal is the lowest-footprint profile: correlation and the trace
	// store off, tiny sketches, aggressive retention, request-phase-only WAF.
	TierMinimal Tier = "minimal"
	// TierStandard is the balanced default (~ current behavior).
	TierStandard Tier = "standard"
	// TierEnterprise maximizes detection depth and history at higher resource cost.
	TierEnterprise Tier = "enterprise"
)

// TierDefaults holds the per-subsystem defaults a tier supplies. A subsystem
// reads its own explicit config first and falls back to the matching field here.
type TierDefaults struct {
	Tier Tier

	// Correlation engine (internal/security/correlation).
	CorrelationEnabled      bool
	CorrelationMaxSources   int
	CorrelationMaxPerSource int

	// Telemetry.
	TraceStoreEnabled bool // open the Pebble trace store at all
	CMSWidth          int  // Count-Min Sketch width
	CMSDepth          int  // Count-Min Sketch depth
	EbpfPollSeconds   int  // eBPF stats poll interval

	// Storage (Pebble + SQL retention).
	RetentionDays       int
	PebbleCacheBytes    int64
	PebbleMemTableBytes int64
	PebbleMaxOpenFiles  int

	// WAF default tier when WafConfig.Tier is empty.
	WAFTier Tier
}

// NormalizeTier coerces an arbitrary string to a known tier, defaulting to
// TierStandard for empty/unknown values.
func NormalizeTier(s string) Tier {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(TierMinimal):
		return TierMinimal
	case string(TierEnterprise):
		return TierEnterprise
	case string(TierStandard):
		return TierStandard
	default:
		return TierStandard
	}
}

// ResolveProfile determines the active tier. The GATEON_PROFILE environment
// variable wins (so a container can pin its footprint regardless of stored
// config); otherwise GlobalConfig.profile is used; otherwise TierStandard.
func ResolveProfile() Tier {
	if env := strings.TrimSpace(os.Getenv("GATEON_PROFILE")); env != "" {
		return NormalizeTier(env)
	}
	if gc := GetGlobalConfig(); gc != nil && gc.Profile != "" {
		return NormalizeTier(gc.Profile)
	}
	return TierStandard
}

// DefaultsFor returns the conservative defaults for a tier.
func DefaultsFor(tier Tier) TierDefaults {
	switch tier {
	case TierMinimal:
		return TierDefaults{
			Tier:                    TierMinimal,
			CorrelationEnabled:      false,
			CorrelationMaxSources:   500,
			CorrelationMaxPerSource: 32,
			TraceStoreEnabled:       false,
			CMSWidth:                512,
			CMSDepth:                3,
			EbpfPollSeconds:         10,
			RetentionDays:           1,
			PebbleCacheBytes:        4 << 20, // 4 MiB
			PebbleMemTableBytes:     1 << 20, // 1 MiB
			PebbleMaxOpenFiles:      50,
			WAFTier:                 TierMinimal,
		}
	case TierEnterprise:
		return TierDefaults{
			Tier:                    TierEnterprise,
			CorrelationEnabled:      true,
			CorrelationMaxSources:   10000,
			CorrelationMaxPerSource: 256,
			TraceStoreEnabled:       true,
			CMSWidth:                4096,
			CMSDepth:                4,
			EbpfPollSeconds:         2,
			RetentionDays:           30,
			PebbleCacheBytes:        32 << 20, // 32 MiB
			PebbleMemTableBytes:     8 << 20,  // 8 MiB
			PebbleMaxOpenFiles:      500,
			WAFTier:                 TierEnterprise,
		}
	default: // TierStandard
		return TierDefaults{
			Tier:                    TierStandard,
			CorrelationEnabled:      true,
			CorrelationMaxSources:   2000,
			CorrelationMaxPerSource: 64,
			TraceStoreEnabled:       true,
			CMSWidth:                2048,
			CMSDepth:                4,
			EbpfPollSeconds:         2,
			RetentionDays:           7,
			PebbleCacheBytes:        8 << 20, // 8 MiB
			PebbleMemTableBytes:     4 << 20, // 4 MiB
			PebbleMaxOpenFiles:      200,
			WAFTier:                 TierStandard,
		}
	}
}

// CurrentTierDefaults resolves the active profile and returns its defaults.
func CurrentTierDefaults() TierDefaults {
	return DefaultsFor(ResolveProfile())
}
