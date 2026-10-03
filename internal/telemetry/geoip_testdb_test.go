// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry/geoiptest"
)

// writeCountryMMDB writes geoiptest's real MaxMind database: 8.8.8.8 is US,
// 203.0.113.9 is CN.
func writeCountryMMDB(t *testing.T) string { return geoiptest.WriteCountryDB(t) }

// TestTheGeneratedTestDatabaseIsReadLikeAMaxMindOne: the gateway's own loader
// and resolver answer from the fixture.
func TestTheGeneratedTestDatabaseIsReadLikeAMaxMindOne(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIP() })
	if err := InitGeoIP(writeCountryMMDB(t)); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{geoiptest.USAddress: "US", geoiptest.CNAddress: "CN"} {
		if got := ResolveCountry(ip); got != want {
			t.Errorf("ResolveCountry(%s) = %q, want %q", ip, got, want)
		}
	}
}
