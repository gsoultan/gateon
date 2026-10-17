// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package cloudmeta

import (
	"net/netip"
	"testing"
)

// withLinkLocal sets the escape hatch for one test.
func withLinkLocal(t *testing.T, allow bool) {
	t.Helper()
	prev := allowLinkLocal
	allowLinkLocal = func() bool { return allow }
	t.Cleanup(func() { allowLinkLocal = prev })
}

func TestIsMetadataAddr(t *testing.T) {
	withLinkLocal(t, false)
	for _, s := range []string{
		"169.254.169.254", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "169.254.170.2",
		"fd00:ec2::254", "100.100.100.200", "168.63.129.16", "169.254.20.10", "fe80::1", "fe80::1%eth0",
	} {
		if !IsMetadataAddr(netip.MustParseAddr(s)) {
			t.Errorf("IsMetadataAddr(%s) = false, want true", s)
		}
	}
	for _, s := range []string{
		"10.0.0.5", "192.168.1.10", "127.0.0.1", "::1", "100.64.0.5", "100.100.100.201",
		"fd00:ec2::253", "64:ff9b::a00:5", "93.184.216.34",
	} {
		if IsMetadataAddr(netip.MustParseAddr(s)) {
			t.Errorf("IsMetadataAddr(%s) = true, want false", s)
		}
	}
}

// TestTheEscapeHatchNeverReopensMetadata: GATEON_ALLOW_LINK_LOCAL_TARGETS
// opens link-local space for the backends that live there (a node-local DNS
// cache, an IPv6 link-local device) and leaves every metadata address shut.
func TestTheEscapeHatchNeverReopensMetadata(t *testing.T) {
	withLinkLocal(t, true)
	for _, s := range []string{"169.254.20.10", "fe80::1"} {
		if IsMetadataAddr(netip.MustParseAddr(s)) {
			t.Errorf("with link-local allowed, IsMetadataAddr(%s) = true, want false", s)
		}
	}
	for _, s := range []string{"169.254.169.254", "::ffff:169.254.169.254", "169.254.170.2", "169.254.0.23", "fd00:ec2::254"} {
		if !IsMetadataAddr(netip.MustParseAddr(s)) {
			t.Errorf("with link-local allowed, IsMetadataAddr(%s) = false, want true", s)
		}
	}
}

func TestIsMetadataHostOrAddr(t *testing.T) {
	withLinkLocal(t, false)
	for _, s := range []string{
		"metadata.google.internal", "METADATA.GOOGLE.INTERNAL.", "metadata.goog",
		"instance-data.ec2.internal", "[fd00:ec2::254]", "169.254.169.254",
	} {
		if !IsMetadataHostOrAddr(s) {
			t.Errorf("IsMetadataHostOrAddr(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"metadata", "metadata-api.internal", "google.internal", "10.0.0.5", ""} {
		if IsMetadataHostOrAddr(s) {
			t.Errorf("IsMetadataHostOrAddr(%q) = true, want false", s)
		}
	}
}

func TestIsMetadataAddrDoesNotAllocate(t *testing.T) {
	a := netip.MustParseAddr("10.0.0.5")
	if n := testing.AllocsPerRun(100, func() { _ = IsMetadataAddr(a) }); n != 0 {
		t.Errorf("IsMetadataAddr allocated %.0f times", n)
	}
}
