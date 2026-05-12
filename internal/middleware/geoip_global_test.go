package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/proto/gateon/v1"
)

type mockGlobalConfigStore struct {
	config *gateonv1.GlobalConfig
}

func (m *mockGlobalConfigStore) Get(ctx context.Context) *gateonv1.GlobalConfig {
	return m.config
}
func (m *mockGlobalConfigStore) Update(ctx context.Context, conf *gateonv1.GlobalConfig) error {
	m.config = conf
	return nil
}
func (m *mockGlobalConfigStore) ConfigFileExists() bool { return true }

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

			handler := GeoIPGlobalWithResolver(store, resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
