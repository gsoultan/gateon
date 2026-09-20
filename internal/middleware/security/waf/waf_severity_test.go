// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/kind"
	"github.com/gsoultan/gateon/internal/security/correlation"
	"github.com/gsoultan/gwaf"
	"github.com/gsoultan/gwaf/types"
)

// A threat's severity is a closed vocabulary — critical, high, medium, low —
// that the dashboard filters on, the SIEM formatter maps to CEF and syslog
// codes, and the correlation engine ranks to decide whether an incident is
// worth mitigating. gwaf names its severities notice, warning, error and
// critical. Only the last of those is a word the rest of gateon knows, so a WAF
// match at any other level was recorded as a string nothing downstream could
// rank, and the correlation engine read it as the lowest severity there is.

func TestWAFThreatSeverityUsesTheDashboardVocabulary(t *testing.T) {
	cases := []struct {
		in   types.Severity
		want string
	}{
		{types.SeverityCritical, kind.SeverityCritical},
		{types.SeverityError, kind.SeverityHigh},
		{types.SeverityWarning, kind.SeverityMedium},
		{types.SeverityNotice, kind.SeverityLow},
	}
	for _, tc := range cases {
		matches := []gwaf.Match{{RuleID: 1, Severity: tc.in}}
		got, _ := wafSeverityAndCategory(matches, gwaf.Decision{})
		if got != tc.want {
			t.Errorf("gwaf %s: recorded severity %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestWAFSeverityIsRankedByTheCorrelationEngine closes the loop: three
// error-level WAF blocks from one source must open a high-severity incident,
// which is the tier the responder restricts on. Under the old vocabulary the
// same three signals produced a "low" incident that was only ever flagged.
func TestWAFSeverityIsRankedByTheCorrelationEngine(t *testing.T) {
	severity, _ := wafSeverityAndCategory([]gwaf.Match{{RuleID: 1, Severity: types.SeverityError}}, gwaf.Decision{})

	engine := correlation.New(correlation.Config{MinSignals: 3})
	var inc correlation.Incident
	var fired bool
	for range 3 {
		inc, fired = engine.Observe(correlation.Signal{
			Type: "waf_blocked", SourceIP: "203.0.113.9", Severity: severity,
		})
	}
	if !fired {
		t.Fatal("three signals from one source did not open an incident")
	}
	if inc.Severity != kind.SeverityHigh {
		t.Fatalf("incident severity %q from three %q WAF blocks, want %q", inc.Severity, severity, kind.SeverityHigh)
	}
}
