// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"testing"

	"github.com/gsoultan/gateon/internal/security/posture"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestPostureReadsTheGlobalWAFAsTheEngineBuildsIt: the server hands the
// posture the engine's reading of the gateway-wide WAF (ADR 0064), tier
// included. At the minimal tier LFI, RCE, PHP, Java, Node.js and scanners are
// already off, so switching SQLi, XSS and protocol off leaves no attack
// family running -- which no reading of the switches alone can see, since six
// of them are unset.
func TestPostureReadsTheGlobalWAFAsTheEngineBuildsIt(t *testing.T) {
	no := false
	store := &mockGlobalReg{config: &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{
		Enabled: true, Tier: "minimal",
		Categories: &gateonv1.WafCategories{Sqli: &no, Xss: &no, Protocol: &no},
	}}}
	pc := postureConfig(context.Background(), postureDeps{globalStore: store})
	pc.Routes = []*gateonv1.Route{{Id: "r", Rule: "PathPrefix(`/`)"}}
	if cov := posture.Coverage(pc); cov.CategoriesOff != 1 || cov.Enforcing != 0 {
		t.Fatalf("coverage = %+v, want the route counted under categoriesOff", cov)
	}
	if mode := wafPosture(pc, posture.Coverage(pc), nil).Mode; mode != string(posture.ModeNoCategories) {
		t.Fatalf("WAF posture mode = %q, want %q", mode, posture.ModeNoCategories)
	}
}
