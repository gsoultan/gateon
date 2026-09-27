// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build openfinding

package api

import (
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// OPEN: the kernel rate limits applyAutomaticMitigation installs on
// neural_sentinel and graph_coordinated_fp findings are invisible to the
// operator. (Their release and the allowlist are fixed and tested in
// automatic_throttle_test.go.) Listing them needs a decision about where a
// throttle -- as opposed to a block -- belongs in the dashboard.
// Run with: go test -tags openfinding -run AutomaticThrottle ./internal/api/

// TestAutomaticThrottleIsVisibleToTheOperator: the mitigation list is where an
// operator looks for what the gateway is doing to an address.
func TestAutomaticThrottleIsVisibleToTheOperator(t *testing.T) {
	const ip = "10.60.0.3"
	s, rec := throttleTestService(t)
	runPasses(s, 3, neuralFinding(ip, 95))
	if rec.throttled([]string{ip}) != 1 {
		t.Fatalf("precondition: the finding did not throttle %s", ip)
	}
	telemetry.FlushThreats()
	mitigations, _ := telemetry.GetIPMitigations(t.Context(), 1000, 0)
	for _, m := range mitigations {
		if m.IP == ip {
			return
		}
	}
	t.Errorf("%s is throttled in the kernel and appears nowhere on the mitigation list (%d entries)", ip, len(mitigations))
}
