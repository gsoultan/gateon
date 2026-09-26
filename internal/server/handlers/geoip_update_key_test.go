// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// savedGeoIPKey is a global config store holding only a saved MaxMind licence
// key, which is all POST /v1/geoip/update reads from it.
type savedGeoIPKey struct {
	config.GlobalConfigStore
	key string
}

func (s savedGeoIPKey) Get(context.Context) *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{Geoip: &gateonv1.GeoIPConfig{MaxmindLicenseKey: s.key}}
}

// TestGeoIPUpdateUsesTheKeyTheSettingsCardSends: "Update now" posts the licence
// key from the settings form, so a key typed but not yet saved can be tried.
// The handler read it through a `json:"maxmind_license_key"` tag, and the card
// sends protojson's "maxmindLicenseKey", which a snake_case tag never matches.
// The typed key was dropped: the update ran with the saved key instead, and
// with none saved it answered 400 "not configured".
func TestGeoIPUpdateUsesTheKeyTheSettingsCardSends(t *testing.T) {
	var used []string
	prev := downloadGeoIP
	downloadGeoIP = func(key string) error {
		used = append(used, key)
		return nil
	}
	t.Cleanup(func() { downloadGeoIP = prev })

	for name, tc := range map[string]struct{ saved, body, want string }{
		"typed over saved":      {saved: "saved-key", body: `{"maxmindLicenseKey":"typed-key"}`, want: "typed-key"},
		"typed with none saved": {saved: "", body: `{"maxmindLicenseKey":"typed-key"}`, want: "typed-key"},
		"proto field name":      {saved: "saved-key", body: `{"maxmind_license_key":"typed-key"}`, want: "typed-key"},
		"saved when none typed": {saved: "saved-key", body: `{}`, want: "saved-key"},
		"saved with no body":    {saved: "saved-key", body: ``, want: "saved-key"},
	} {
		t.Run(name, func(t *testing.T) {
			used = nil
			mux := http.NewServeMux()
			registerGeoIPHandlers(mux, savedGeoIPKey{key: tc.saved})
			req := httptest.NewRequest(http.MethodPost, "/v1/geoip/update", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body)
			}
			if len(used) != 1 || used[0] != tc.want {
				t.Errorf("downloaded with %q, want [%q]", used, tc.want)
			}
		})
	}
}
