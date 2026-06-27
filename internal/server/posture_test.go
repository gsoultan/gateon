package server

import (
	"context"
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
