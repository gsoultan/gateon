// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/middleware/security"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestGeoIPStatusSaysWhetherTheGeofenceWorks is the dashboard half of truth
// T1: the GeoIP card warned only that the map would be empty, while the
// country block list beside it refused no one. The status the card reads now
// says what the country lists do.
func TestGeoIPStatusSaysWhetherTheGeofenceWorks(t *testing.T) {
	_ = telemetry.CloseGeoIP()
	store := fixedGlobalStore{&gateonv1.GlobalConfig{
		Geoip: &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"CN"}},
	}}
	mux := http.NewServeMux()
	registerGeoIPHandlers(mux, store)
	req := httptest.NewRequest(http.MethodGet, "/v1/geoip/status", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey,
		&auth.Claims{ID: "a-1", Username: "admin", Role: auth.RoleAdmin}))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/geoip/status: %d", rr.Code)
	}
	var body struct {
		Exists   bool `json:"exists"`
		Geofence struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
		} `json:"geofence"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Exists || body.Geofence.State != security.GeoFenceBlockListInactive || body.Geofence.Reason == "" {
		t.Errorf("status = %+v, want no database and state %q with a reason", body, security.GeoFenceBlockListInactive)
	}
}
