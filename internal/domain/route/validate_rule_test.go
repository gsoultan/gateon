// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package route

import (
	"errors"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// ValidateRule refuses what the router cannot read, saying where, and leaves
// alone what a TCP/UDP route legitimately has: no rule, or the dashboard's
// L4() (ADR 0043).
func TestValidateRule(t *testing.T) {
	for _, tc := range []struct {
		typ, rule string
		invalid   bool
		missing   bool
	}{
		{"http", "PathPrefix(`/api`)", false, false},
		{"http", "Hots(`a.example`)", true, false},
		{"http", "   ", false, true},
		{"grpc", "", false, true},
		{"tcp", "", false, false},
		{"udp", "L4()", false, false},
		{"tcp", "PathPrefix(`/x", true, false},
	} {
		err := ValidateRule(&gateonv1.Route{Type: tc.typ, Rule: tc.rule})
		switch {
		case tc.invalid:
			if !errors.Is(err, ErrInvalidRule) || !strings.Contains(err.Error(), "at character") {
				t.Errorf("%s %q: got %v, want ErrInvalidRule with a position", tc.typ, tc.rule, err)
			}
		case tc.missing:
			if err == nil || !strings.Contains(err.Error(), "missing rule") {
				t.Errorf("%s %q: got %v, want missing rule", tc.typ, tc.rule, err)
			}
		case err != nil:
			t.Errorf("%s %q: refused: %v", tc.typ, tc.rule, err)
		}
	}
}
