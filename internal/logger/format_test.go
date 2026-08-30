// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package logger

import "testing"

// TestConfiguredFormatWins is the regression guard: the encoding was chosen by
// ENV=production alone, so log.format did nothing and an operator who asked for
// JSON got text — which a log pipeline parsing JSON cannot read at all.
func TestConfiguredFormatWins(t *testing.T) {
	for _, tc := range []struct {
		name        string
		format      string
		development bool
		prod        bool
		wantJSON    bool
	}{
		{"json requested on a dev host", "json", true, false, true},
		{"json requested, nothing else set", "json", false, false, true},
		{"text requested on a production host", "text", false, true, false},
		{"case and spacing tolerated", "  JSON  ", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveJSONOutput(tc.format, tc.development, tc.prod); got != tc.wantJSON {
				t.Fatalf("resolveJSONOutput(%q, dev=%v, prod=%v) = %v, want %v",
					tc.format, tc.development, tc.prod, got, tc.wantJSON)
			}
		})
	}
}

// development means text when no explicit format is given, and loses to one that
// is — the more specific setting wins.
func TestDevelopmentImpliesTextButYieldsToFormat(t *testing.T) {
	if resolveJSONOutput("", true, true) {
		t.Error("development=true on a production host should still give text")
	}
	if !resolveJSONOutput("json", true, false) {
		t.Error("an explicit json format should beat development=true")
	}
}

// An install that sets neither field must behave exactly as before: JSON in
// production, text elsewhere.
func TestUnsetFieldsPreserveTheEnvBehaviour(t *testing.T) {
	if !resolveJSONOutput("", false, true) {
		t.Error("production with nothing configured should still be JSON")
	}
	if resolveJSONOutput("", false, false) {
		t.Error("non-production with nothing configured should still be text")
	}
	// An unrecognised format is not a third mode; it falls through to the
	// derived default rather than silently picking one.
	if !resolveJSONOutput("yaml", false, true) {
		t.Error("an unknown format should fall back to the derived default")
	}
}
