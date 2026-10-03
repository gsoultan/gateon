// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/geoiptest"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// globalGeoStatus sends a request from ip through the global geofence built
// as the entrypoints build it, resolving with the gateway's own resolver.
func globalGeoStatus(t *testing.T, geo *gateonv1.GeoIPConfig, ip string) int {
	t.Helper()
	store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{Geoip: geo}}
	h := GeoIPGlobal(t.Context(), store)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = net.JoinHostPort(ip, "40000")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func noGeoDatabase(t *testing.T) {
	t.Helper()
	_ = telemetry.CloseGeoIP()
	t.Cleanup(func() { _ = telemetry.CloseGeoIP() })
}

// TestTheGlobalGeofenceWithADatabase drives the real resolver against a real
// database: the configuration the save now insists on is the one that works.
func TestTheGlobalGeofenceWithADatabase(t *testing.T) {
	noGeoDatabase(t)
	if err := telemetry.InitGeoIP(geoiptest.WriteCountryDB(t)); err != nil {
		t.Fatal(err)
	}
	block := &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"CN"}}
	if got := globalGeoStatus(t, block, geoiptest.CNAddress); got != http.StatusForbidden {
		t.Errorf("CN client against a CN block list: %d, want 403", got)
	}
	if got := globalGeoStatus(t, block, geoiptest.USAddress); got != http.StatusOK {
		t.Errorf("US client against a CN block list: %d, want 200", got)
	}
	if state, _ := GeoFenceState(block, telemetry.GeoIPLoaded()); state != GeoFenceActive {
		t.Errorf("state with a database = %q, want %q", state, GeoFenceActive)
	}
}

// TestTheGlobalGeofenceWithoutADatabaseSaysWhatItDoes pins the runtime
// decision of ADR 0044 for a list stored before the save refused it, or whose
// database went away: an allow list fails closed, a block list refuses no one
// -- refusing everyone in its place would be an outage nobody asked for -- and
// the state the dashboard shows says which, instead of "saved".
func TestTheGlobalGeofenceWithoutADatabaseSaysWhatItDoes(t *testing.T) {
	noGeoDatabase(t)
	block := &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"CN", "RU"}}
	if got := globalGeoStatus(t, block, geoiptest.CNAddress); got != http.StatusOK {
		t.Errorf("block list with no database: %d, want 200 (served, and said loudly)", got)
	}
	if state, reason := GeoFenceState(block, false); state != GeoFenceBlockListInactive || reason == "" {
		t.Errorf("block list state = %q (%q), want %q with a reason", state, reason, GeoFenceBlockListInactive)
	}

	allow := &gateonv1.GeoIPConfig{Enabled: true, AllowedCountries: []string{"US"}}
	if got := globalGeoStatus(t, allow, geoiptest.USAddress); got != http.StatusForbidden {
		t.Errorf("allow list with no database: %d, want 403 (fail closed)", got)
	}
	if state, _ := GeoFenceState(allow, false); state != GeoFenceRefusingAll {
		t.Errorf("allow list state = %q, want %q", state, GeoFenceRefusingAll)
	}

	off := &gateonv1.GeoIPConfig{Enabled: false, BlockedCountries: []string{"CN"}}
	if state, _ := GeoFenceState(off, false); state != GeoFenceOff {
		t.Errorf("disabled geofence state = %q, want %q", state, GeoFenceOff)
	}
}

// TestARouteGeofenceRefusesWhatIsNotACountry: on a route deny list "China"
// matched nothing and saved.
func TestARouteGeofenceRefusesWhatIsNotACountry(t *testing.T) {
	path := geoiptest.WriteCountryDB(t)
	if _, err := NewGeoIP(map[string]string{"db_path": path, "deny_countries": "CN,China"}); err == nil {
		t.Error("a route geofence naming \"China\" built")
	}
	mw, err := NewGeoIP(map[string]string{"db_path": path, "deny_countries": "CN"})
	if err != nil {
		t.Fatalf("a valid route geofence was refused: %v", err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = net.JoinHostPort(geoiptest.CNAddress, "40000")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("CN client on a CN route deny list: %d, want 403", rr.Code)
	}
}
