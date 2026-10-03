// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"path/filepath"
	"testing"
)

// TestABadDatabasePathKeepsTheLoadedDatabase: InitGeoIP closed the loaded
// database before opening the new one, so saving a db_path that does not
// open -- a typo, or an upload the reader rejects -- took country resolution
// away until restart, and every country geofence with it: the block list then
// refused no one and the allow list refused everyone (ADR 0044).
func TestABadDatabasePathKeepsTheLoadedDatabase(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIP() })
	if err := InitGeoIP(writeCountryMMDB(t)); err != nil {
		t.Fatal(err)
	}
	if err := InitGeoIP(filepath.Join(t.TempDir(), "missing.mmdb")); err == nil {
		t.Fatal("a path that does not exist opened")
	}
	if !GeoIPLoaded() {
		t.Error("GeoIPLoaded() = false after a failed reload; the loaded database should still be in force")
	}
	if got := ResolveCountry("8.8.8.8"); got != "US" {
		t.Errorf("ResolveCountry(8.8.8.8) after a failed reload = %q, want US from the database still loaded", got)
	}
}

// TestACountryDatabaseAloneResolvesCountries: the Country edition was loaded
// as a "fallback" and then never asked; with no City database every address
// resolved to "XX". A Country database is all a geofence needs.
func TestACountryDatabaseAloneResolvesCountries(t *testing.T) {
	t.Cleanup(func() { _ = CloseGeoIP() })
	if GeoIPLoaded() {
		t.Fatal("precondition: no database loaded")
	}
	if got := ResolveCountry("203.0.113.9"); got != "XX" {
		t.Fatalf("with no database: %q, want XX", got)
	}
	if err := InitGeoIPCountry(writeCountryMMDB(t)); err != nil {
		t.Fatal(err)
	}
	if !GeoIPLoaded() {
		t.Error("GeoIPLoaded() = false with a Country database loaded")
	}
	if got := ResolveCountry("203.0.113.9"); got != "CN" {
		t.Errorf("ResolveCountry with only a Country database = %q, want CN", got)
	}
	if err := CloseGeoIP(); err != nil {
		t.Fatal(err)
	}
	if GeoIPLoaded() {
		t.Error("GeoIPLoaded() = true after CloseGeoIP")
	}
	if got := ResolveCountry("203.0.113.9"); got != "XX" {
		t.Errorf("after CloseGeoIP: %q, want XX (a cached answer from the closed database outlived it)", got)
	}
}
