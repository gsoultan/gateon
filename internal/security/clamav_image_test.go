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
		"clamav/clamav@sha256:0123abcd", "docker.io/clamav/clamav-debian:1.4",
	} {
		if err := ValidateClamAVImage(ok); err != nil {
			t.Errorf("image %q refused: %v", ok, err)
		}
	}
}

// TestClamAVImageMustComeFromAClamAVRepository: any image reference was
// accepted, so an administrator's session -- a stolen one included -- could
// have the gateway's host run a container of its choosing (ADR 0097).
func TestClamAVImageMustComeFromAClamAVRepository(t *testing.T) {
	t.Setenv(EnvClamAVImageRepositories, "")
	for _, bad := range []string{
		"alpine", "attacker/clamav", "evil.example/clamav/clamav:1.4", "clamav/clamav-evil",
		"registry.example:5000/sec/clamav@sha256:0123abcd", "clamav", "library/clamav",
	} {
		if err := ValidateClamAVImage(bad); err == nil {
			t.Errorf("image %q accepted; it is not a ClamAV repository", bad)
		}
		if err := ValidateClamAVImageSyntax(bad); err != nil {
			t.Errorf("image %q refused as syntax: %v", bad, err)
		}
	}
}

// A mirror is the host's decision, made in the gateway's environment, and
// allows that repository at any tag or digest and nothing beside it.
func TestClamAVImageMirrorIsAllowedByTheHostEnvironment(t *testing.T) {
	t.Setenv(EnvClamAVImageRepositories, " registry.example:5000/sec/clamav , other/one")
	for _, ok := range []string{
		"registry.example:5000/sec/clamav", "registry.example:5000/sec/clamav:1.4",
		"registry.example:5000/sec/clamav@sha256:0123abcd", "other/one:2", "clamav/clamav",
	} {
		if err := ValidateClamAVImage(ok); err != nil {
			t.Errorf("image %q refused: %v", ok, err)
		}
	}
	if err := ValidateClamAVImage("registry.example:5000/sec/other"); err == nil {
		t.Error("a repository beside the mirror was accepted")
	}
}
