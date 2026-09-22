// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIsCountryCode covers the validation that stops a client-written header
// becoming an unbounded Prometheus label.
//
// CF-IPCountry was read with neither a trusted-peer check nor any format
// check, and the value flows into RequestsByCountryTotal and from there into
// a threat record's CountryCode. A label is a map key kept for the life of the
// process, and the header cap is 1 MiB, so "a two-letter country code" was
// whatever the client felt like sending.
func TestIsCountryCode(t *testing.T) {
	valid := []string{"US", "GB", "gb", "Us", "XX", "ZZ"}
	for _, v := range valid {
		if !isCountryCode(v) {
			t.Errorf("isCountryCode(%q) = false, want true: a real country code "+
				"was rejected and the country breakdown would lose it", v)
		}
	}

	invalid := []string{"", "U", "USA", "12", "U1", "U-", "  ", "<script>", "ZZQ000001"}
	for _, v := range invalid {
		if isCountryCode(v) {
			t.Errorf("isCountryCode(%q) = true, want false: this becomes a "+
				"permanent metric series the client chose", v)
		}
	}
}

// TestGetCountryIgnoresAMalformedCloudflareHeader is the end-to-end half: an
// unusable value must fall through to the resolver rather than be taken at
// face value.
func TestGetCountryIgnoresAMalformedCloudflareHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("CF-IPCountry", "ZZQ000001-not-a-country")

	// trustCloudflare=true is the only path that reads the header at all.
	if got := GetCountry(r, true); got == "ZZQ000001-NOT-A-COUNTRY" {
		t.Error("a malformed CF-IPCountry was used verbatim as the country; it " +
			"becomes a Prometheus label and a stored threat field")
	}
}

// TestGetCountryHonoursAValidCloudflareHeader keeps the fix from discarding
// the real thing along with the malformed.
func TestGetCountryHonoursAValidCloudflareHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	r.Header.Set("CF-IPCountry", "gb")

	if got := GetCountry(r, true); got != "GB" {
		t.Errorf("GetCountry = %q, want %q: a valid lower-case code from a "+
			"trusted Cloudflare edge was dropped", got, "GB")
	}
}
