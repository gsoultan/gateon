// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAnalyzeConfigDoesNotRecommendTheRemovedDoSSwitch is truth NEW-6: the
// advisory warned "DoS protection is off -- Enable WAF DoS protection" on every
// install. ADR 0044 removed that switch from the dashboard because it selects
// no WAF rule; setting it through the API cleared the warning and changed
// nothing. The advisory now never names it, and the stored flag cannot change
// what it says.
func TestAnalyzeConfigDoesNotRecommendTheRemovedDoSSwitch(t *testing.T) {
	cov := wafCoverage{Total: 2, Enforcing: 2}
	for _, dos := range []bool{false, true} {
		cfg := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: true, DosProtection: dos}}
		for _, in := range analyzeConfig(t.Context(), cfg, cov).Insights {
			text := strings.ToLower(in.Title + " " + in.Description + " " + in.Recommendation + " " + in.SuggestedConfig)
			if strings.Contains(text, "dos protection") || strings.Contains(text, "dos_protection") {
				t.Errorf("dos_protection=%v: insight %q names the removed DoS switch: %q", dos, in.Title, text)
			}
		}
	}
}

// TestAnalyzeConfigRateLimitInsightCountsRoutes replaces that check with the
// control that does bound a bursty client: a ratelimit or inflightreq
// middleware on the route. Like bot management (ADR 0048), it is counted on
// the routes that carry it.
func TestAnalyzeConfigRateLimitInsightCountsRoutes(t *testing.T) {
	cfg := &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true}}
	cases := []struct {
		limited int
		want    string
	}{
		{0, "Rate limiting covers no route"},
		{1, "Rate limiting covers 1 of 2 routes"},
		{2, ""},
	}
	for _, tc := range cases {
		cov := wafCoverage{Total: 2, Enforcing: 2, RateLimited: tc.limited}
		resp := analyzeConfig(t.Context(), cfg, cov)
		got := hasInsight(resp, "Rate limiting covers")
		if got != (tc.want != "") {
			t.Fatalf("%d of 2 routes limited: rate-limit insight reported = %v, want %v", tc.limited, got, tc.want != "")
		}
		if tc.want != "" && !hasInsight(resp, tc.want) {
			t.Errorf("%d of 2 routes limited: no insight titled %q", tc.limited, tc.want)
		}
	}
}
