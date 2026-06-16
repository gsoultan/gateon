package telemetry

import "testing"

// TestResolveASNWithoutDatabase verifies that ASN resolution degrades
// gracefully: when no ASN database is loaded (the default for deployments that
// only ship GeoLite2-City), ResolveASN must return an empty string for every
// input rather than panicking or returning a placeholder.
func TestResolveASNWithoutDatabase(t *testing.T) {
	geoMu.Lock()
	prev := asnDB
	asnDB = nil
	geoMu.Unlock()
	t.Cleanup(func() {
		geoMu.Lock()
		asnDB = prev
		geoMu.Unlock()
	})

	tests := []struct {
		name string
		ip   string
	}{
		{"EmptyIP", ""},
		{"InvalidIP", "not-an-ip"},
		{"PublicIPv4", "8.8.8.8"},
		{"PrivateIPv4", "192.168.1.1"},
		{"IPv6", "2001:4860:4860::8888"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveASN(tc.ip); got != "" {
				t.Errorf("ResolveASN(%q) = %q; want empty string when ASN DB is not loaded", tc.ip, got)
			}
		})
	}
}

// TestInitGeoIPASNMissingFileIsNotFatal verifies that initializing the ASN
// reader with an empty path (and no default/env database present) is a no-op
// and does not return an error, keeping the database optional.
func TestInitGeoIPASNMissingFileIsNotFatal(t *testing.T) {
	t.Setenv("GATEON_GEOIP_ASN_DB_PATH", "")

	geoMu.Lock()
	prev := asnDB
	asnDB = nil
	geoMu.Unlock()
	t.Cleanup(func() {
		geoMu.Lock()
		asnDB = prev
		geoMu.Unlock()
	})

	if err := InitGeoIPASN(""); err != nil {
		t.Fatalf("InitGeoIPASN(\"\") returned error %v; want nil when no database is configured", err)
	}
}

// TestInitGeoIPASNInvalidFile verifies that pointing the ASN reader at a
// non-existent file surfaces an error so misconfiguration is reported.
func TestInitGeoIPASNInvalidFile(t *testing.T) {
	geoMu.Lock()
	prev := asnDB
	asnDB = nil
	geoMu.Unlock()
	t.Cleanup(func() {
		geoMu.Lock()
		asnDB = prev
		geoMu.Unlock()
	})

	if err := InitGeoIPASN("testdata/does-not-exist.mmdb"); err == nil {
		t.Fatal("InitGeoIPASN with a missing explicit path = nil; want an error")
	}
}
