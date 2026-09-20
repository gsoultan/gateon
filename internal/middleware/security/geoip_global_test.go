// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func TestGeoIPGlobal(t *testing.T) {
	tests := []struct {
		name           string
		config         *gateonv1.GeoIPConfig
		country        string
		expectedStatus int
	}{
		{
			name: "Allowed country",
			config: &gateonv1.GeoIPConfig{
				Enabled:          true,
				BlockedCountries: []string{"CN", "RU"},
			},
			country:        "US",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Blocked country",
			config: &gateonv1.GeoIPConfig{
				Enabled:          true,
				BlockedCountries: []string{"CN", "RU"},
			},
			country:        "CN",
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "Not in allow list",
			config: &gateonv1.GeoIPConfig{
				Enabled:          true,
				AllowedCountries: []string{"US", "CA"},
			},
			country:        "FR",
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "In allow list",
			config: &gateonv1.GeoIPConfig{
				Enabled:          true,
				AllowedCountries: []string{"US", "CA"},
			},
			country:        "CA",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Disabled geofencing",
			config: &gateonv1.GeoIPConfig{
				Enabled:          false,
				BlockedCountries: []string{"CN"},
			},
			country:        "CN",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockGlobalConfigStore{
				config: &gateonv1.GlobalConfig{Geoip: tt.config},
			}
			resolver := func(ip string) string { return tt.country }

			handler := GeoIPGlobalWithResolver(t.Context(), store, resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "http://example.com", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %v, got %v", tt.expectedStatus, rr.Code)
			}
		})
	}
}
