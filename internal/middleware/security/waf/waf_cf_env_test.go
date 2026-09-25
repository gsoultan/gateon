// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package waf

import (
	"os"
	"os/exec"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware/security"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestWAFHonoursTheTrustCloudflareEnvironmentVariable: both WAF paths took
// Cloudflare trust from the WAF config's own flag alone, so with
// GATEON_TRUST_CLOUDFLARE_HEADERS=true the WAF still judged, logged and
// allowlisted every request by the Cloudflare edge address it arrived from.
// The variable is read once per process, so the check runs in a child.
func TestWAFHonoursTheTrustCloudflareEnvironmentVariable(t *testing.T) {
	if os.Getenv("GATEON_TEST_CF_ENV_CHILD") == "1" {
		w := &gateonv1.WafConfig{Enabled: true, UseCrs: true}
		if !globalWAFConfig(w, config.TierStandard, security.Deps{}).TrustCloudflare {
			t.Error("global WAF does not trust CF-Connecting-IP")
		}
		for _, useCRS := range []bool{true, false} {
			cfg := map[string]string{}
			mergeGlobalWAFDefaults(cfg, security.Deps{GlobalStore: &mockGlobalConfigStore{
				config: &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, UseCrs: useCRS}},
			}})
			if !parseWAFConfig(cfg).TrustCloudflare {
				t.Errorf("use_crs=%v: route WAF does not trust CF-Connecting-IP (trust_cloudflare_headers=%q)",
					useCRS, cfg["trust_cloudflare_headers"])
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestWAFHonoursTheTrustCloudflareEnvironmentVariable$", "-test.count=1")
	cmd.Env = append(os.Environ(), "GATEON_TEST_CF_ENV_CHILD=1", "GATEON_TRUST_CLOUDFLARE_HEADERS=true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// TestRouteWAFInheritsCloudflareTrustWithoutCRS: the dashboard's trust switch
// lives on the global WAF config, and a route WAF took it only when the global
// WAF also had use_crs on. Trust is about where the gateway sits, not about
// the rule set, so a route WAF under a global WAF without CRS judged requests
// by the Cloudflare edge address they came from.
func TestRouteWAFInheritsCloudflareTrustWithoutCRS(t *testing.T) {
	if os.Getenv("GATEON_TRUST_CLOUDFLARE_HEADERS") != "" {
		t.Skip("the environment already turns trust on")
	}
	cfg := map[string]string{}
	mergeGlobalWAFDefaults(cfg, security.Deps{GlobalStore: &mockGlobalConfigStore{
		config: &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{Enabled: true, TrustCloudflareHeaders: true}},
	}})
	if !parseWAFConfig(cfg).TrustCloudflare {
		t.Errorf("route WAF does not trust CF-Connecting-IP (trust_cloudflare_headers=%q)",
			cfg["trust_cloudflare_headers"])
	}
}
