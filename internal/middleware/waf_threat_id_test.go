// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.

package middleware

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// securityThreatIDLimit is the width of security_threats.id after migration 62.
//
// The threat record's primary key has a bound, and the code that builds it has
// to respect one. SQLite declares the column TEXT and silently accepts anything,
// so an oversized key is invisible there and rejected on Postgres and MySQL —
// which is how it shipped: the WAF blocked correctly, logged that it had, and
// every threat vanished before reaching the Security Hub.
const securityThreatIDLimit = 255

// TestThreatIDIsBoundedByRouteName pins the property that regressed: the key
// must not grow with an input nobody controls.
//
// Route names are written by operators. The dev gateway ships one 46 characters
// long, and nothing stops a longer one, so a key built by interpolating the
// route name has no upper bound at all. The route is already carried in its own
// route_id column, which is why dropping it from the key costs nothing.
func TestThreatIDIsBoundedByRouteName(t *testing.T) {
	t.Parallel()

	for _, routeID := range []string{
		"api",
		"API (own WAF override + rate limit, strips /api)",
		strings.Repeat("very-long-route-name-", 40),
	} {
		o := wafObservation{
			request: httptest.NewRequest("GET", "/api/x?id=1", nil),
			routeID: routeID,
			cfg:     WAFConfig{RouteID: routeID},
		}

		got := o.threat("203.0.113.10")
		if len(got.ID) > securityThreatIDLimit {
			t.Errorf("threat ID is %d chars for a %d-char route name; the column holds %d\n  id=%q",
				len(got.ID), len(routeID), securityThreatIDLimit, got.ID)
		}
		if got.ID == "" {
			t.Error("threat carries no ID; it would be unattributable in the dashboard")
		}
		// The route still has to reach the record — just in its own field.
		if got.RouteID != routeID {
			t.Errorf("RouteID = %q, want %q; dropping it from the key must not drop it from the row",
				got.RouteID, routeID)
		}
	}
}

// TestThreatIDsAreDistinct guards the other half of removing a component from a
// key: two threats must still not collide.
func TestThreatIDsAreDistinct(t *testing.T) {
	t.Parallel()

	o := wafObservation{
		request: httptest.NewRequest("GET", "/api/x?id=1", nil),
		routeID: "api",
		cfg:     WAFConfig{RouteID: "api"},
	}

	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		id := o.threat("203.0.113.10").ID
		if seen[id] {
			t.Fatalf("duplicate threat ID %q after %d records; the primary key would reject it", id, i)
		}
		seen[id] = true
	}
}
