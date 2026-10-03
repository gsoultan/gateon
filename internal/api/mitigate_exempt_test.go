// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestMitigateTellsTheTruthAboutAnExemptAddress: blocking 127.0.0.1, or an
// address in GATEON_MITIGATION_ALLOWLIST, answered "Source X successfully
// mitigated." while every request from it was still served -- the request path
// exempts both (identity.AddressBlocked). The block is recorded, so it is
// listed and takes effect if the exemption is lifted, but the answer says it is
// not enforced, and why.
func TestMitigateTellsTheTruthAboutAnExemptAddress(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "mitigate.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	mitigation.SetAllowlist(mitigation.ParseAllowlist("198.51.100.0/24"))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	for _, tc := range []struct{ ip, says string }{
		{"127.0.0.1", "loopback"},
		{"::1", "loopback"},
		{"198.51.100.7", "GATEON_MITIGATION_ALLOWLIST"},
	} {
		res, err := (&ApiService{}).MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: tc.ip, Type: "IP"})
		if err != nil {
			t.Fatalf("%s: %v", tc.ip, err)
		}
		if res.Success || !strings.Contains(res.Message, "not enforced") || !strings.Contains(res.Message, tc.says) {
			t.Errorf("%s: success=%v %q, want a failure saying the block is recorded but not enforced (%s)",
				tc.ip, res.Success, res.Message, tc.says)
		}
		if !telemetry.IsIPMitigated(tc.ip) {
			t.Errorf("%s: the block was not recorded", tc.ip)
		}
	}

	res, err := (&ApiService{}).MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: "203.0.113.44", Type: "IP"})
	if err != nil || !res.Success {
		t.Fatalf("an ordinary address: success=%v %q err=%v, want success", res.GetSuccess(), res.GetMessage(), err)
	}
}
