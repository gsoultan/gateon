// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestMatchPlaybookDashboardTriggers is the regression test for playbooks that
// never fired. The dashboard's "Trigger Event" select stores camelCase values
// ("wafThreat", "highAnomaly", "impossibleTravel", "authFailure"), the proto
// documents the same triggers as snake_case, and matchPlaybook compared the
// trigger to SecurityThreat.Type -- whose real values are "waf_block",
// "brute_force_attempt" and so on. Only "All Threats" ever matched; every
// playbook with a specific trigger was configured, displayed, and silent.
func TestMatchPlaybookDashboardTriggers(t *testing.T) {
	t.Parallel()

	m := &AlertingManager{}
	for _, tc := range []struct {
		name   string
		pb     *gateonv1.AlertPlaybook
		threat telemetry.SecurityThreat
		want   bool
	}{
		{"dashboard wafThreat matches a WAF block",
			&gateonv1.AlertPlaybook{EventType: "wafThreat"},
			telemetry.SecurityThreat{Type: "waf_block", Category: "waf", Score: 80}, true},
		{"documented waf_threat matches a WAF block",
			&gateonv1.AlertPlaybook{EventType: "waf_threat"},
			telemetry.SecurityThreat{Type: "waf_block", Category: "waf", Score: 80}, true},
		{"wafThreat does not match a honeypot hit",
			&gateonv1.AlertPlaybook{EventType: "wafThreat"},
			telemetry.SecurityThreat{Type: "honeypot_triggered", Category: "deception", Score: 100}, false},
		{"highAnomaly at threshold matches any detection",
			&gateonv1.AlertPlaybook{EventType: "highAnomaly", Threshold: 50},
			telemetry.SecurityThreat{Type: "sqli_detected", Score: 60}, true},
		{"high_anomaly under threshold does not",
			&gateonv1.AlertPlaybook{EventType: "high_anomaly", Threshold: 50},
			telemetry.SecurityThreat{Type: "sqli_detected", Score: 10}, false},
		{"impossibleTravel matches the zero-trust detector",
			&gateonv1.AlertPlaybook{EventType: "impossibleTravel"},
			telemetry.SecurityThreat{Type: "impossible_travel", Score: 90}, true},
		{"authFailure matches brute force",
			&gateonv1.AlertPlaybook{EventType: "authFailure"},
			telemetry.SecurityThreat{Type: "brute_force_attempt", Category: "brute_force", Score: 70}, true},
		{"exact type still matches",
			&gateonv1.AlertPlaybook{EventType: "sqli_detected"},
			telemetry.SecurityThreat{Type: "sqli_detected", Score: 60}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := m.matchPlaybook(tc.pb, tc.threat); got != tc.want {
				t.Errorf("matchPlaybook(%q, %q) = %v, want %v", tc.pb.EventType, tc.threat.Type, got, tc.want)
			}
		})
	}
}
