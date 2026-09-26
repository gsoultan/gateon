// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestTrustCloudflareEnvironmentVariableIsHonoured: the README and the
// Cloudflare Tunnel guide tell an operator behind Cloudflare to set
// GATEON_TRUST_CLOUDFLARE_HEADERS=true. EffectiveTrustCloudflare read the
// variable only when the global config had no WAF section, and
// NewGlobalRegistry always creates one, so the variable did nothing: every
// client appeared as a Cloudflare edge address to the rate limiter, the IP
// filter and the management allowlist.
//
// The variable is read once per process, so the check runs in a child with it
// set.
func TestTrustCloudflareEnvironmentVariableIsHonoured(t *testing.T) {
	if os.Getenv("GATEON_TEST_CF_ENV_CHILD") == "1" {
		NewGlobalRegistry(filepath.Join(t.TempDir(), "global.json"))
		if !EffectiveTrustCloudflare() {
			t.Fatal("GATEON_TRUST_CLOUDFLARE_HEADERS=true, yet CF-Connecting-IP is not trusted")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTrustCloudflareEnvironmentVariableIsHonoured$", "-test.count=1")
	cmd.Env = append(os.Environ(), "GATEON_TEST_CF_ENV_CHILD=1", "GATEON_TRUST_CLOUDFLARE_HEADERS=true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
