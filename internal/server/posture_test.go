// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"encoding/json"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestClamavPostureEnabledFollowsMalwareDetection guards the fix for the
// Security Hub showing ClamAV "Enabled" when it was never turned on: the default
// global config always populates a non-nil Waf.Clamav block, so Enabled must be
// derived from the actual malware_detection toggle, not the config block's mere
// presence.
func TestClamavPostureEnabledFollowsMalwareDetection(t *testing.T) {
	cases := []struct {
		name             string
		malwareDetection bool
		clamavBlock      *gateonv1.ClamavConfig
		wantEnabled      bool
	}{
		{
			name:             "config block present but scanning off",
			malwareDetection: false,
			clamavBlock:      &gateonv1.ClamavConfig{}, // mirrors the default config
			wantEnabled:      false,
		},
		{
			name:             "scanning on",
			malwareDetection: true,
			clamavBlock:      &gateonv1.ClamavConfig{},
			wantEnabled:      true,
		},
		{
			name:             "scanning on without a clamav block",
			malwareDetection: true,
			clamavBlock:      nil,
			wantEnabled:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &mockGlobalReg{config: &gateonv1.GlobalConfig{
				Waf: &gateonv1.WafConfig{
					MalwareDetection: tc.malwareDetection,
					Clamav:           tc.clamavBlock,
				},
			}}
			// clamav manager nil: Installed stays false, Enabled is what we assert.
			p := clamavPosture(context.Background(), store, nil)
			if p.Enabled != tc.wantEnabled {
				t.Errorf("Enabled = %v, want %v", p.Enabled, tc.wantEnabled)
			}
			if p.Installed {
				t.Errorf("Installed = true, want false (no manager)")
			}
		})
	}
}

// TestPostureSignatureEngineIsNotHardCoded is T4: the report said
// "signatures: enabled, 11 rules" on an install with no middleware at all,
// where nothing scans an upload.
func TestPostureSignatureEngineIsNotHardCoded(t *testing.T) {
	store := &mockGlobalReg{config: &gateonv1.GlobalConfig{}}
	report := newPostureProvider(postureDeps{globalStore: store})(context.Background())
	if report.Signatures.Enabled || report.Signatures.RuleCount != 0 {
		t.Fatalf("signatures = %+v with no file_security route, want disabled and no rules", report.Signatures)
	}
}

// TestPostureWAFReportsModeNotAutoUpdate is T12 and T26: the WAF's mode is in
// the report, and the repurposed auto_update_rules flag is reported as what it
// does (load rules already on disk), not as rules that update themselves.
func TestPostureWAFReportsModeNotAutoUpdate(t *testing.T) {
	store := &mockGlobalReg{config: &gateonv1.GlobalConfig{
		Waf: &gateonv1.WafConfig{Enabled: true, AuditOnly: true, AutoUpdateRules: true},
	}}
	report := newPostureProvider(postureDeps{globalStore: store})(context.Background())
	if report.WAF.Mode != "detect" {
		t.Fatalf("waf mode = %q, want detect for an audit-only WAF", report.WAF.Mode)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		WAF   map[string]any `json:"waf"`
		Score map[string]any `json:"score"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire.WAF["autoUpdate"]; ok {
		t.Fatalf("waf still reports autoUpdate: %s", raw)
	}
	if wire.WAF["customRulesFromDisk"] != true {
		t.Fatalf("waf.customRulesFromDisk = %v, want true: %s", wire.WAF["customRulesFromDisk"], raw)
	}
	if _, ok := wire.Score["percent"]; !ok {
		t.Fatalf("report has no score.percent: %s", raw)
	}
}
