// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package correlation

import "testing"

// emittedThreatTypes are the Type values gateon actually writes into
// security_threats. They are listed by hand, and that is the point: the map
// under test is keyed by these strings, and nothing in the compiler connects the
// two. The first version of this map had "waf_block" while the WAF has always
// recorded "waf_"+action — so the most common threat gateon produces, and every
// mitigation derived from one, showed an empty MITRE column in the Incidents
// tab. Nothing failed; the annotation was simply never there.
//
// Add a threat type here when you add one to a middleware. A missing entry is a
// column that renders blank rather than an error anyone would notice.
var emittedThreatTypes = []string{
	// internal/middleware/waf_telemetry.go — "waf_" + action
	"waf_blocked",
	"waf_detected",
	// internal/telemetry — mitigation records
	"user_mitigation",
	"ip_mitigation",
	// middleware sources
	"bot_detected",
	"cors_violation",
	"geoip_block",
	"honeypot_triggered",
	"rate_limit",
	"reputation_block",
	"security_threat",
}

// TestEveryEmittedThreatTypeMapsToATechnique is the drift guard.
func TestEveryEmittedThreatTypeMapsToATechnique(t *testing.T) {
	t.Parallel()

	for _, threatType := range emittedThreatTypes {
		got := Techniques(threatType)
		if len(got) == 0 {
			t.Errorf("threat type %q maps to no MITRE technique; the Incidents tab renders an empty ATT&CK column for it", threatType)
			continue
		}
		for _, tech := range got {
			if tech.ID == "" || tech.Name == "" || tech.Tactic == "" {
				t.Errorf("threat type %q maps to an incomplete technique %+v", threatType, tech)
			}
		}
	}
}

// TestTechniquesReturnsACopy pins the documented contract: the caller may retain
// or mutate the result without corrupting the table for every later lookup.
func TestTechniquesReturnsACopy(t *testing.T) {
	t.Parallel()

	first := Techniques("waf_blocked")
	if len(first) == 0 {
		t.Fatal("waf_blocked maps to nothing")
	}
	original := first[0].ID
	first[0].ID = "MUTATED"

	if second := Techniques("waf_blocked"); second[0].ID != original {
		t.Errorf("mutating a returned technique changed the table: got %q, want %q", second[0].ID, original)
	}
}

// TestUnknownThreatTypeIsNotAnError keeps the documented fallback: an unmapped
// type yields nothing rather than panicking a dashboard request.
func TestUnknownThreatTypeIsNotAnError(t *testing.T) {
	t.Parallel()

	if got := Techniques("something_nobody_has_written_yet"); got != nil {
		t.Errorf("unknown threat type returned %+v, want nil", got)
	}
}
