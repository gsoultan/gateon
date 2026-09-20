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

	mw, err := NewHeaders(cfg)
	if err != nil {
		t.Fatalf("NewHeaders: %v", err)
	}

	var first string
	for i := 0; i < 50; i++ {
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

	// "del" sorts before "set", so the delete applies first and the set wins.
	// Asserted so the ordering rule is written down rather than merely stable.
	if first != "kept" {
		t.Errorf("X-Contested = %q, want %q: rules apply in sorted config-key "+
			"order, so del_request_ precedes set_request_", first, "kept")
	}
}
