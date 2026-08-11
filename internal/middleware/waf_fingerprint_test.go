// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import "testing"

// The WAF engine is memoized on WAFConfig.Fingerprint, so anything that changes
// which rules load or which exceptions apply has to be in the hash. A field
// left out is not a cosmetic bug: the first route to build an engine wins, and
// every later route with a different policy silently gets that one. A route
// that enabled SSRF protection would run without it, and a route that enabled
// no profile would inherit another tenant's suppressions.
//
// These are the two fields v0.4.0 added.

func TestFingerprintSeparatesSSRFProtection(t *testing.T) {
	t.Parallel()

	off := WAFConfig{ParanoiaLevel: 1}
	on := WAFConfig{ParanoiaLevel: 1, EnableSSRFProtection: true}

	if off.Fingerprint() == on.Fingerprint() {
		t.Error("SSRF protection is not in the config fingerprint; a route enabling it would " +
			"share the cached engine of one that did not, and run without the rule")
	}
}

func TestFingerprintSeparatesAppProfiles(t *testing.T) {
	t.Parallel()

	none := WAFConfig{ParanoiaLevel: 1}
	wp := WAFConfig{ParanoiaLevel: 1, AppProfiles: []string{"wordpress"}}
	laravel := WAFConfig{ParanoiaLevel: 1, AppProfiles: []string{"laravel"}}
	both := WAFConfig{ParanoiaLevel: 1, AppProfiles: []string{"wordpress", "laravel"}}

	for _, tc := range []struct {
		a, b WAFConfig
		name string
	}{
		{none, wp, "no profile vs wordpress"},
		{wp, laravel, "wordpress vs laravel"},
		{wp, both, "wordpress vs wordpress+laravel"},
	} {
		if tc.a.Fingerprint() == tc.b.Fingerprint() {
			t.Errorf("%s share a fingerprint; one route's suppressions would leak into the other", tc.name)
		}
	}
}

// A different spelling of the same profile is the same engine. Building two
// identical engines is a memory cost with no benefit, and the WAF is the most
// expensive thing gateon caches.
func TestFingerprintCollapsesEquivalentProfileSpellings(t *testing.T) {
	t.Parallel()

	a := WAFConfig{ParanoiaLevel: 1, AppProfiles: []string{"WordPress"}}
	b := WAFConfig{ParanoiaLevel: 1, AppProfiles: []string{"wordpress"}}
	c := WAFConfig{ParanoiaLevel: 1, AppProfiles: []string{"  wp  "}}

	if a.Fingerprint() != b.Fingerprint() || b.Fingerprint() != c.Fingerprint() {
		t.Error("equivalent spellings of one profile build separate engines")
	}
}
