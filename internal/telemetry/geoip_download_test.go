// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

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
