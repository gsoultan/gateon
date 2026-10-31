// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"testing"
)

// TestFileScanDefaultsFollowTheProfile: the scanner's two memory bounds used
// to be fixed at 4 concurrent scans of 64 MiB on every tier. Each scan holds
// the body and then the part it inspects, so that is about 512 MiB resident
// at the worst case -- a quarter of the 2 GB minimal target, for one
// middleware. The bounds now come from the resource profile when a route
// sets neither, so minimal is sized to what it can hold and standard keeps
// exactly what every existing install already has.
//
// Root cause: withDefaults read package constants, not TierDefaults.
func TestFileScanDefaultsFollowTheProfile(t *testing.T) {
	t.Setenv(fileScanMaxConcurrentEnv, "")
	t.Setenv(fileScanMaxMBEnv, "")

	cases := []struct {
		profile    string
		concurrent int
		bytes      int64
		worstCase  int64 // 2 x concurrent x bytes
	}{
		{"minimal", 2, 16 << 20, 64 << 20},
		{"standard", 4, 64 << 20, 512 << 20},
		{"enterprise", 8, 64 << 20, 1 << 30},
	}
	for _, c := range cases {
		t.Run(c.profile, func(t *testing.T) {
			t.Setenv("GATEON_PROFILE", c.profile)
			got := FileSecurityConfig{}.withDefaults()
			if got.MaxConcurrentScans != c.concurrent || got.MaxScanBytes != c.bytes {
				t.Fatalf("%s: defaults = %d scans x %d bytes, want %d x %d",
					c.profile, got.MaxConcurrentScans, got.MaxScanBytes, c.concurrent, c.bytes)
			}
			if worst := 2 * int64(got.MaxConcurrentScans) * got.MaxScanBytes; worst != c.worstCase {
				t.Fatalf("%s: worst-case resident = %d, want %d", c.profile, worst, c.worstCase)
			}
		})
	}

	t.Run("minimal holds a bounded share of a 2 GB host", func(t *testing.T) {
		t.Setenv("GATEON_PROFILE", "minimal")
		got := FileSecurityConfig{}.withDefaults()
		if worst := 2 * int64(got.MaxConcurrentScans) * got.MaxScanBytes; worst > 128<<20 {
			t.Fatalf("minimal's worst-case resident is %d MiB; must stay at or under 128 MiB", worst>>20)
		}
	})
}

// TestFileScanDefaultsOverrides: a route's own setting wins over the profile,
// the env var wins over the profile for routes that set none, and a bad env
// value keeps the profile's bound rather than lifting it.
func TestFileScanDefaultsOverrides(t *testing.T) {
	t.Setenv("GATEON_PROFILE", "minimal")

	t.Run("route config wins", func(t *testing.T) {
		t.Setenv(fileScanMaxConcurrentEnv, "9")
		t.Setenv(fileScanMaxMBEnv, "9")
		got := FileSecurityConfig{MaxConcurrentScans: 3, MaxScanBytes: 5 << 20}.withDefaults()
		if got.MaxConcurrentScans != 3 || got.MaxScanBytes != 5<<20 {
			t.Fatalf("route setting was overridden: %d x %d", got.MaxConcurrentScans, got.MaxScanBytes)
		}
	})

	t.Run("env override is honoured in MiB", func(t *testing.T) {
		t.Setenv(fileScanMaxConcurrentEnv, "6")
		t.Setenv(fileScanMaxMBEnv, "32")
		got := FileSecurityConfig{}.withDefaults()
		if got.MaxConcurrentScans != 6 || got.MaxScanBytes != 32<<20 {
			t.Fatalf("env override not applied: %d x %d", got.MaxConcurrentScans, got.MaxScanBytes)
		}
	})

	t.Run("bad env keeps the profile bound", func(t *testing.T) {
		t.Setenv(fileScanMaxConcurrentEnv, "0")
		t.Setenv(fileScanMaxMBEnv, "huge")
		got := FileSecurityConfig{}.withDefaults()
		if got.MaxConcurrentScans != 2 || got.MaxScanBytes != 16<<20 {
			t.Fatalf("bad env lifted the bound: %d x %d", got.MaxConcurrentScans, got.MaxScanBytes)
		}
	})
}
