// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func geoPreflight(path string) *http.Request {
	r := httptest.NewRequest(http.MethodOptions, "http://example.com"+path, nil)
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Access-Control-Request-Method", "GET")
	return r
}

// TestGeoIPGlobalDoesNotSkipAPreflight: a geofence is an operator's deny
// decision about where a client is, and a client does not stop being there by
// announcing a preflight.
func TestGeoIPGlobalDoesNotSkipAPreflight(t *testing.T) {
	cases := []struct {
		name    string
		country string
		want    int
		reach   bool
	}{
		{"blocked country", "CN", http.StatusForbidden, false},
		// The positive control: the fix must not turn legitimate browser CORS
		// from a permitted country into a refusal.
		{"permitted country", "US", http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
				Geoip: &gateonv1.GeoIPConfig{Enabled: true, BlockedCountries: []string{"CN", "RU"}},
			}}
			var reached bool
			h := GeoIPGlobalWithResolver(t.Context(), store, func(string) string { return tc.country })(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusOK)
				}))

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, geoPreflight("/"))

			if reached != tc.reach {
				t.Errorf("backend reached = %v, want %v", reached, tc.reach)
			}
			if rr.Code != tc.want {
				t.Errorf("status = %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

// TestGeoIPRouteLevelDoesNotSkipAPreflight covers the route-chain copy, which
// is the one a preflight actually reached: the global geofence runs in the
// HTTP entrypoint's chain, behind transform.GlobalCORS, but this one sits in
// the router's chain, which a plaintext smart-TCP entrypoint reaches through
// BaseHandler with no CORS termination in front of it.
//
// The runtime is built directly with no database. serve refuses an
// unparseable client address before it consults one, so that refusal is enough
// to show the preflight no longer short-circuits the middleware -- and
// building GeoIP() itself would need a MaxMind fixture in the checkout.
func TestGeoIPRouteLevelDoesNotSkipAPreflight(t *testing.T) {
	rt := geoIPRuntime{allow: map[string]bool{"US": true}, deny: map[string]bool{}}

	var reached bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	req := geoPreflight("/")
	req.RemoteAddr = "not-an-address"
	rr := httptest.NewRecorder()
	rt.serve(next, rr, req)

	if reached {
		t.Error("a preflight skipped the route-level geofence entirely and " +
			"reached the backend without its address ever being resolved")
	}
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}
