// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestAnalyzeConfigReportsAManagementPlaneAnyoneCanReach holds the management
// insight to what the listeners enforce.
//
// Two paths put the management API in front of any client. The dedicated
// listener binds to every interface and admits any address when its allowlist
// covers the whole address space -- the shipped default, which the server
// itself warns about at startup. And allow_public_management serves the API on
// every entrypoint, where neither allowed_ips (the dedicated listener's list)
// nor allowed_hosts (a Host header the client writes) is consulted. The
// advisory only looked at the second, and only when both lists were empty; the
// shipped allowlist is 0.0.0.0/0 and ::/0, never empty, so it could not fire.
func TestAnalyzeConfigReportsAManagementPlaneAnyoneCanReach(t *testing.T) {
	for _, env := range []string{"GATEON_MANAGEMENT_BIND", "GATEON_MANAGEMENT_ALLOWED_IPS", "GATEON_ALLOW_PUBLIC_MANAGEMENT"} {
		t.Setenv(env, "")
	}
	everyone := []string{"0.0.0.0/0", "::/0"}
	cases := []struct {
		name    string
		mgmt    *gateonv1.ManagementConfig
		exposed bool
	}{
		{name: "shipped default", mgmt: &gateonv1.ManagementConfig{Bind: "0.0.0.0", AllowedIps: everyone}, exposed: true},
		{name: "public management with the shipped allowlist",
			mgmt:    &gateonv1.ManagementConfig{Bind: "127.0.0.1", AllowedIps: everyone, AllowPublicManagement: true},
			exposed: true},
		{name: "public management with a narrow allowlist",
			mgmt:    &gateonv1.ManagementConfig{Bind: "127.0.0.1", AllowedIps: []string{"10.0.0.0/8"}, AllowPublicManagement: true},
			exposed: true},
		{name: "every interface, admin network only",
			mgmt: &gateonv1.ManagementConfig{Bind: "0.0.0.0", AllowedIps: []string{"10.0.0.0/8"}}, exposed: false},
		{name: "loopback, open allowlist",
			mgmt: &gateonv1.ManagementConfig{Bind: "127.0.0.1", AllowedIps: everyone}, exposed: false},
	}
	for _, tc := range cases {
		cfg := &gateonv1.GlobalConfig{Management: tc.mgmt}
		got := hasInsight(analyzeConfig(t.Context(), cfg), "Management")
		if got != tc.exposed {
			t.Errorf("%s: management exposure insight reported = %v, want %v", tc.name, got, tc.exposed)
		}
	}
}
