// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// gomemlimitLine matches the value the chart renders for GOMEMLIMIT.
var gomemlimitLine = regexp.MustCompile(`name: GOMEMLIMIT\s+value: "([^"]*)"`)

// renderGOMEMLIMIT runs `helm template` over charts/gateon with the given
// memory limit and returns the GOMEMLIMIT it sets, or "" when it sets none.
func renderGOMEMLIMIT(t *testing.T, helm, limit string) string {
	t.Helper()
	chart := filepath.Join("..", "..", "charts", "gateon")
	// #nosec G204 -- a test driving the helm binary over this repository's chart.
	out, err := exec.Command(helm, "template", "t", chart,
		"--set", "resources.limits.memory="+limit).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template with memory limit %s: %v\n%s", limit, err, out)
	}
	m := gomemlimitLine.FindSubmatch(out)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// TestHelmDerivedGOMEMLIMITFollowsFractionalLimits covers the chart's
// gateon.memoryLimit helper, which derives GOMEMLIMIT as 80% of
// resources.limits.memory.
//
// It parsed the number with sprig's `int`, which returns 0 for anything with a
// decimal point, so a limit of 1.5Gi -- an ordinary Kubernetes quantity --
// rendered GOMEMLIMIT="0MiB". The Go runtime accepts that as a limit of zero
// bytes and collects continuously: a probe allocating 800 MB ran 1,841 GCs
// and took 10.6x as long as with no limit. The pod does not crash, so nothing
// says why the gateway is slow.
//
// The arithmetic only exists inside helm, so this drives helm itself; a
// fixture of its output would test the fixture.
func TestHelmDerivedGOMEMLIMITFollowsFractionalLimits(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; the chart's GOMEMLIMIT arithmetic runs only under helm")
	}
	for _, tc := range []struct{ limit, want string }{
		{"2Gi", "1638MiB"}, // the default; unchanged by the fix
		{"1.5Gi", "1228MiB"},
		{"0.5Gi", "409MiB"},
		{"2.5Gi", "2048MiB"},
		{"1536Mi", "1228MiB"},
		{"750.5Mi", "600MiB"},
		// Too small to leave a whole MiB: no GOMEMLIMIT rather than a zero one.
		{"1Mi", ""},
		// A suffix the helper does not parse keeps the runtime default rather
		// than guessing, as before.
		{"2G", ""},
	} {
		t.Run(tc.limit, func(t *testing.T) {
			got := renderGOMEMLIMIT(t, helm, tc.limit)
			if got != tc.want {
				t.Errorf("resources.limits.memory=%s rendered GOMEMLIMIT=%q, want %q", tc.limit, got, tc.want)
			}
			if got == "0MiB" {
				t.Error("GOMEMLIMIT=0MiB makes the Go runtime collect continuously")
			}
		})
	}
}
