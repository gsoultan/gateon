// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	dto "github.com/prometheus/client_model/go"
)

// The enforcement cache in front of ip_mitigations was a fixed 1,000 answers
// on every tier, so a gateway seeing more distinct clients than that in a
// mitigation epoch re-read the database for most of them. It is now sized by
// the resource profile, and the environment variable still wins over it.
func TestMitigationCacheIsSizedByTheProfile(t *testing.T) {
	for _, tier := range []config.Tier{config.TierMinimal, config.TierStandard, config.TierEnterprise} {
		t.Run(string(tier), func(t *testing.T) {
			t.Setenv("GATEON_PROFILE", string(tier))
			freshStore(t)
			want := config.DefaultsFor(tier).MitigationCacheEntries
			if want <= defaultUnmitigatedCacheSize {
				t.Fatalf("%s sizes the cache at %d, no more than the old fixed %d", tier, want, defaultUnmitigatedCacheSize)
			}
			got := mitigationCacheCapacity(t)
			if int(got) != want {
				t.Fatalf("%s: enforcement cache capacity %v, want the profile's %d", tier, got, want)
			}
		})
	}
	t.Run("env overrides the profile", func(t *testing.T) {
		t.Setenv("GATEON_PROFILE", string(config.TierEnterprise))
		t.Setenv(envUnmitigatedCacheSize, "777")
		freshStore(t)
		if got := mitigationCacheCapacity(t); got != 777 {
			t.Fatalf("capacity %v with %s=777", got, envUnmitigatedCacheSize)
		}
	})
}

func mitigationCacheCapacity(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := TelemetryCacheCapacity.WithLabelValues(cacheNameUnmitigated).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}
