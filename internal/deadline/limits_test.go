// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package deadline

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/config"
)

func TestStreamLimitsEndAtTakesWhicheverBoundComesFirst(t *testing.T) {
	start := time.Unix(1000, 0)
	last := start.Add(10 * time.Second)
	cases := []struct {
		name   string
		limits StreamLimits
		want   time.Time
	}{
		{"idle_only", StreamLimits{Idle: 5 * time.Second}, last.Add(5 * time.Second)},
		{"lifetime_only", StreamLimits{MaxLifetime: time.Minute}, start.Add(time.Minute)},
		{"idle_first", StreamLimits{Idle: 5 * time.Second, MaxLifetime: time.Minute}, last.Add(5 * time.Second)},
		{"lifetime_first", StreamLimits{Idle: 5 * time.Second, MaxLifetime: 12 * time.Second}, start.Add(12 * time.Second)},
		{"neither", StreamLimits{}, time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.limits.endAt(start, last); !got.Equal(tc.want) {
				t.Fatalf("endAt = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCurrentStreamLimitsComeFromTheTierUnlessOverridden(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "minimal")
	tier := config.DefaultsFor(config.TierMinimal)

	t.Setenv(IdleTimeoutEnv, "")
	t.Setenv(MaxLifetimeEnv, "")
	if got := CurrentStreamLimits(); got.Idle != tier.StreamIdleTimeout || got.MaxLifetime != tier.StreamMaxLifetime {
		t.Fatalf("unset: %+v, want the minimal tier's %v / %v", got, tier.StreamIdleTimeout, tier.StreamMaxLifetime)
	}

	t.Setenv(IdleTimeoutEnv, "90s")
	t.Setenv(MaxLifetimeEnv, "0")
	if got := CurrentStreamLimits(); got.Idle != 90*time.Second || got.MaxLifetime != 0 {
		t.Fatalf("overridden: %+v, want 90s and 0 (disabled)", got)
	}

	t.Setenv(IdleTimeoutEnv, "soon")
	t.Setenv(MaxLifetimeEnv, "-5m")
	if got := CurrentStreamLimits(); got.Idle != tier.StreamIdleTimeout || got.MaxLifetime != 0 {
		t.Fatalf("invalid: %+v, want the tier's idle for an unparseable value and 0 for a negative one", got)
	}
}
