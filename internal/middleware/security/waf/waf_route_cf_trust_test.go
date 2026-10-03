// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestRouteWAFRefusesACloudflareTrustThatDisagrees: a route WAF's own "Trust
// Cloudflare Headers" switch let anyone who may edit a middleware move a trust
// boundary only an administrator may (ADR 0040), and the address the WAF
// inspects was the one the entrypoint had already resolved from the global
// setting anyway. A value that disagrees with the gateway's is refused at
// save, as every other middleware's is (ADR 0046); one that agrees, or none,
// still builds.
func TestRouteWAFRefusesACloudflareTrustThatDisagrees(t *testing.T) {
	t.Setenv("GATEON_TRUST_CLOUDFLARE_HEADERS", "")
	InvalidateWAFCache()
	t.Cleanup(InvalidateWAFCache)
	for _, global := range []bool{false, true} {
		d := security.Deps{GlobalStore: &mockGlobalConfigStore{config: &gateonv1.GlobalConfig{
			Waf: &gateonv1.WafConfig{TrustCloudflareHeaders: global},
		}}}
		disagree, agree := "true", "false"
		if global {
			disagree, agree = "false", "true"
		}
		_, err := NewWAF(map[string]string{"route": "cf", keyTrustCloudflare: disagree}, d)
		if err == nil || !strings.Contains(err.Error(), "Trust Cloudflare IPs/Headers") {
			t.Errorf("global trust %t, route %s: err = %v, want a refusal naming the global setting", global, disagree, err)
		}
		for _, v := range []string{agree, ""} {
			if _, err := NewWAF(map[string]string{"route": "cf", keyTrustCloudflare: v}, d); err != nil {
				t.Errorf("global trust %t, route %q: refused: %v", global, v, err)
			}
		}
	}
}
