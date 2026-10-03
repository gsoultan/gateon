// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/geoiptest"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// saveGeo saves the stored global config with geo replaced, as an
// administrator, through the path PUT /v1/global, Connect and gRPC share.
func saveGeo(t *testing.T, svc *ApiService, geo *gateonv1.GeoIPConfig) error {
	t.Helper()
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&auth.Claims{ID: "a-1", Username: "admin", Role: auth.RoleAdmin})
	next, ok := proto.Clone(svc.Globals.Get(ctx)).(*gateonv1.GlobalConfig)
	if !ok {
		t.Fatal("clone")
	}
	next.Geoip = geo
	_, err := svc.UpdateGlobalConfig(ctx, &gateonv1.UpdateGlobalConfigRequest{Config: next})
	return err
}

func geoSaveService(t *testing.T) *ApiService {
	t.Helper()
	_ = telemetry.CloseGeoIP()
	t.Cleanup(func() { _ = telemetry.CloseGeoIP() })
	return &ApiService{Globals: config.NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))}
}

// TestACountryListIsRefusedWithoutADatabase is truth T1: on a default install
// -- GeoIP enabled, no licence key, so no database -- "Blocked Countries"
// [US, CN, RU] saved with success and blocked nobody, because every client
// resolved to the unknown country "XX". The save is refused now, saying what
// to install and where.
func TestACountryListIsRefusedWithoutADatabase(t *testing.T) {
	svc := geoSaveService(t)
	err := saveGeo(t, svc, &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"US", "CN", "RU"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("blocked countries saved with no GeoIP database: err = %v, want InvalidArgument", err)
	}
	for _, want := range []string{"GeoIP database", "Settings > GeoIP", "GATEON_GEOIP_DB_PATH"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
	if got := svc.Globals.Get(context.Background()).GetGeoip().GetBlockedCountries(); len(got) != 0 {
		t.Errorf("the refused list was stored: %v", got)
	}

	if err := saveGeo(t, svc, &gateonv1.GeoIPConfig{Enabled: true, AllowedCountries: []string{"US"}}); err == nil {
		t.Error("an allow list with no database -- which refuses every request -- saved")
	}
}

// TestACountryListSavesWithADatabase is the positive control: naming a
// database that opens, or having one loaded, makes the same list savable.
func TestACountryListSavesWithADatabase(t *testing.T) {
	svc := geoSaveService(t)
	path := geoiptest.WriteCountryDB(t)
	err := saveGeo(t, svc, &gateonv1.GeoIPConfig{Enabled: true, DbPath: path, BlockedCountries: []string{"CN"}})
	if err != nil {
		t.Fatalf("a list with a database path that opens was refused: %v", err)
	}

	svc = geoSaveService(t)
	if err := telemetry.InitGeoIP(path); err != nil {
		t.Fatal(err)
	}
	if err := saveGeo(t, svc, &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"CN"}}); err != nil {
		t.Fatalf("a list with a database loaded was refused: %v", err)
	}
}

// TestAGeofenceSaveRefusesWhatIsNotACountry: "USA" or "China" never matches
// the two-letter code a lookup returns, so it blocked no one.
func TestAGeofenceSaveRefusesWhatIsNotACountry(t *testing.T) {
	svc := geoSaveService(t)
	if err := telemetry.InitGeoIP(geoiptest.WriteCountryDB(t)); err != nil {
		t.Fatal(err)
	}
	err := saveGeo(t, svc, &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"USA"}})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), `"USA"`) {
		t.Fatalf("err = %v, want InvalidArgument naming \"USA\"", err)
	}
}

// TestAnUnchangedListDoesNotBlockOtherSaves: a list stored before this check
// existed, or before its database went away, is reported by the geofence at
// runtime; refusing every unrelated settings save until it is fixed would
// hold the whole Settings page hostage to it.
func TestAnUnchangedListDoesNotBlockOtherSaves(t *testing.T) {
	svc := geoSaveService(t)
	stored := &gateonv1.GlobalConfig{Geoip: &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"CN"}}}
	if err := svc.Globals.Update(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	if err := saveGeo(t, svc, &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{" cn"}}); err != nil {
		t.Fatalf("re-saving the stored list was refused: %v", err)
	}
}
