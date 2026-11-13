// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"strings"
	"testing"
)

// TestClamAVImageIsNeverReadAsADockerOption: the configured image is passed
// to `docker run` and `docker pull` as an argument. Docker reads an argument
// that starts with a dash as an option, so "--privileged" in that field was a
// flag and not an image.
func TestClamAVImageIsNeverReadAsADockerOption(t *testing.T) {
	for _, bad := range []string{
		"--privileged", "-v=/:/host", "clamav/clamav --privileged", "clamav\tclamav",
		"clamav;id", "$(id)", ".hidden", strings.Repeat("a", maxClamAVImageLen+1),
	} {
		if err := ValidateClamAVImage(bad); err == nil {
			t.Errorf("image %q accepted", bad)
		}
	}
	for _, ok := range []string{
		"", "clamav/clamav", "clamav/clamav:1.4", "clamav/clamav:stable_base",
		"registry.example:5000/sec/clamav@sha256:0123abcd",
	} {
		if err := ValidateClamAVImage(ok); err != nil {
			t.Errorf("image %q refused: %v", ok, err)
		}
	}
}
