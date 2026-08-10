// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import "testing"

// TestManagementExposureDetection pins the predicate behind the startup
// warning. The shipped default — bind 0.0.0.0 with an allowlist of 0.0.0.0/0
// and ::/0 — publishes the dashboard and the whole management API on every
// network the host is attached to. That is correct inside a container and wrong
// on a public host, so the gateway states the exposure rather than guessing;
// this test is what keeps the statement accurate.
func TestManagementExposureDetection(t *testing.T) {
	tests := []struct {
		name       string
		bind       string
		allowedIPs []string
		wantOpen   bool
	}{
		{"shipped default is world-open", "0.0.0.0", []string{"0.0.0.0/0", "::/0"}, true},
		{"wildcard v6 with open allowlist", "::", []string{"::/0"}, true},
		{"wildcard with no allowlist constrains nothing", "0.0.0.0", nil, true},
		{"empty bind is a wildcard", "", []string{"0.0.0.0/0"}, true},
		{"wildcard bind but a real allowlist", "0.0.0.0", []string{"10.0.0.0/8"}, false},
		{"loopback bind", "127.0.0.1", []string{"0.0.0.0/0"}, false},
		{"loopback bind and loopback allowlist", "127.0.0.1", []string{"127.0.0.1", "::1"}, false},
		{"specific address", "10.1.2.3", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isWildcardBind(tc.bind) && allowsEveryAddress(tc.allowedIPs)
			if got != tc.wantOpen {
				t.Errorf("bind=%q allowed=%v: world-open = %v, want %v",
					tc.bind, tc.allowedIPs, got, tc.wantOpen)
			}
		})
	}
}
