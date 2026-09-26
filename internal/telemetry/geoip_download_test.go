// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// TestDownloadGeoIPEditionEncodesTheLicenceKey: the key reaches the download
// URL from the settings card as well as from global config, and it was
// formatted into the query unescaped -- so a key containing "&" or "#" added
// parameters to the request sent to MaxMind, or cut it short.
func TestDownloadGeoIPEditionEncodesTheLicenceKey(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.WriteHeader(http.StatusNotFound) // stop before any archive is read
	}))
	t.Cleanup(srv.Close)
	prev := geoIPDownloadURL
	geoIPDownloadURL = srv.URL + "/app/geoip_download"
	t.Cleanup(func() { geoIPDownloadURL = prev })

	const key = "abc&edition_id=GeoLite2-ASN#rest"
	_ = downloadGeoIPEdition(key, geoIPEdition{
		id:       editionCity,
		destPath: filepath.Join(t.TempDir(), "GeoLite2-City.mmdb"),
		reload:   func(string) error { return nil },
	})
	if got == nil {
		t.Fatal("the download never reached the server")
	}
	if k := got.Get("license_key"); k != key {
		t.Errorf("license_key = %q, want the whole key %q", k, key)
	}
	if ids := got["edition_id"]; len(ids) != 1 || ids[0] != editionCity {
		t.Errorf("edition_id = %q, want only %q", ids, editionCity)
	}
}

// TestDownloadGeoIPEditionDoesNotLeakLicenseKey: the licence key travels in the
// download URL, and a transport failure comes back as *url.Error, whose message
// embeds that URL. The worker logs the error and /v1/geoip/update writes it to
// the response, so the key ended up in the system log stream.
func TestDownloadGeoIPEditionDoesNotLeakLicenseKey(t *testing.T) {
	// A loopback port that nothing listens on: the dial fails immediately.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	prev := geoIPDownloadURL
	geoIPDownloadURL = "http://" + addr + "/app/geoip_download"
	t.Cleanup(func() { geoIPDownloadURL = prev })

	const key = "SECRET-LICENSE-KEY-1234"
	err = downloadGeoIPEdition(key, geoIPEdition{
		id:       editionCity,
		destPath: filepath.Join(t.TempDir(), "GeoLite2-City.mmdb"),
		reload:   func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected the download to fail")
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("licence key leaked into the error: %v", err)
	}
}
