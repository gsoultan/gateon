// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package transform

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHeaderOpsAreOrderStable pins a property the old implementation did not
// have. It applied header rules by ranging the config map, and Go randomises
// map iteration order per range, so a config carrying two rules for the same
// header -- set_request_X and del_request_X, say -- applied them in a
// different order on consecutive requests. The header was present or absent
// depending on nothing the operator could see.
//
// Resolving the rules once, sorted by config key, makes the outcome a property
// of the config rather than of the runtime. Against the old code this test
// fails intermittently, which is the worst way for a test to fail, so the
// assertion is repeated rather than run once.
func TestHeaderOpsAreOrderStable(t *testing.T) {
	cfg := map[string]string{
		"set_request_X-Contested": "kept",
		"del_request_X-Contested": "",
		"add_request_X-Other":     "a",
	}

	var first string
	for i := 0; i < 50; i++ {
		// Rebuilt every iteration on purpose. headerOpsFor ranges and sorts the
		// config map at construction, so hoisting this out of the loop -- which
		// is what the first version of this test did -- replays one already
		// resolved slice fifty times and cannot observe map-order
		// nondeterminism at all.
		mw, err := NewHeaders(cfg)
		if err != nil {
			t.Fatalf("NewHeaders: %v", err)
		}

		var seen string
		h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen = r.Header.Get("X-Contested")
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

		if i == 0 {
			first = seen
			continue
		}
		if seen != first {
			t.Fatalf("iteration %d saw X-Contested=%q, iteration 0 saw %q; "+
				"the same config produced two different requests", i, seen, first)
		}
	}

	// Sorting full config keys puts the action prefixes in the order
	// add_ < del_ < set_, so set always wins and del always beats add. That is
	// the precedence, and it is worth stating because it is stronger than
	// "stable": ranging the map could previously apply set and then add, which
	// leaves the header carrying two values. That outcome is now unreachable.
	if first != "kept" {
		t.Errorf("X-Contested = %q, want %q: rules apply in sorted config-key "+
			"order, so del_request_ precedes set_request_", first, "kept")
	}
}
