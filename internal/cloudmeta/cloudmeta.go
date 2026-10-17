// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package cloudmeta knows where cloud instance metadata services answer, so
// that nothing the gateway connects to on someone else's behalf reaches one
// (ADR 0078).
//
// A metadata service hands whatever can reach it the instance's identity and,
// on most clouds, short-lived credentials for its role: on EC2 a GET of
// 169.254.169.254/latest/meta-data/iam/security-credentials/<role>, after an
// IMDSv2 token PUT a proxy forwards as readily as a GET. A data-plane backend,
// a diagnostics probe and the technology probe are all connections the
// gateway opens from the instance, so each one refuses these addresses. This
// package is the one list they share; it does no I/O and does not allocate.
package cloudmeta

import (
	"net/netip"
	"os"
	"strings"
	"sync"
)

// fixed are the metadata addresses that are refused whatever the escape hatch
// says. The link-local ones are listed even though all of 169.254.0.0/16 is
// refused by default, because GATEON_ALLOW_LINK_LOCAL_TARGETS opens the range
// and must not reopen these.
var fixed = [...]netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, Oracle, DigitalOcean, OpenStack
	netip.MustParseAddr("169.254.170.2"),   // AWS ECS task metadata and credentials
	netip.MustParseAddr("169.254.170.23"),  // AWS EKS Pod Identity agent
	netip.MustParseAddr("169.254.0.23"),    // Tencent Cloud
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud: in 100.64/10, not link-local
	netip.MustParseAddr("168.63.129.16"),   // Azure WireServer: a public address only the VM reaches
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6 (Nitro)
	netip.MustParseAddr("fd00:ec2::23"),    // AWS EKS Pod Identity agent over IPv6
}

// hosts are the names metadata services are published under. A name is
// resolved by the dialer and caught there by its address; these are refused
// by name as well so that a save is refused before anything resolves them,
// and so that a name whose address is not on the list (Equinix publishes a
// routable one) is still refused where the target is written.
//
// The short names "metadata" (GCP) and "instance-data" (EC2) are not listed:
// they are also what a Kubernetes Service or a compose service is plausibly
// called, and where they do resolve to a metadata service the dialer refuses
// the address they resolve to.
var hosts = map[string]bool{
	"metadata.google.internal":     true,
	"metadata.goog":                true,
	"instance-data.ec2.internal":   true,
	"metadata.tencentyun.com":      true,
	"metadata.platformequinix.com": true,
	"metadata.packet.net":          true, // Equinix Metal's former name
}

// nat64 is the well-known NAT64 prefix (RFC 6052). 64:ff9b::a9fe:a9fe is
// 169.254.169.254 to a NAT64 gateway, which translates and connects to it.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// Embedded is the IPv4 address a reaches when a is an IPv4-mapped IPv6
// address or one in the well-known NAT64 prefix, and a itself otherwise, with
// any zone dropped. Every policy that classifies an address calls it first, so
// that ::ffff:169.254.169.254 and 64:ff9b::a9fe:a9fe are judged as the IPv4
// address they connect to.
func Embedded(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return a
}

// IsMetadataAddr reports whether a connection to a would reach a cloud
// instance metadata service: one of the fixed metadata addresses, or any
// link-local unicast address (169.254.0.0/16, fe80::/10) unless the operator
// has allowed link-local targets. IPv4-mapped and NAT64 forms are judged as
// the IPv4 address they reach. It does not allocate.
func IsMetadataAddr(a netip.Addr) bool {
	a = Embedded(a)
	for _, m := range fixed {
		if a == m {
			return true
		}
	}
	return a.IsLinkLocalUnicast() && !allowLinkLocal()
}

// IsMetadataHost reports whether name is one metadata services are published
// under, compared case-insensitively and without a trailing dot.
func IsMetadataHost(name string) bool {
	return hosts[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")]
}

// IsMetadataHostOrAddr is IsMetadataHost for a name and IsMetadataAddr for an
// address literal, bracketed or not.
func IsMetadataHostOrAddr(host string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		return IsMetadataAddr(a)
	}
	return IsMetadataHost(h)
}

// AllowLinkLocalEnv is the environment variable that permits link-local
// targets other than the fixed metadata addresses. It exists for the backends
// that genuinely live there: a node-local DNS cache on 169.254.20.10, a device
// reached by its IPv6 link-local address. It is read once, at the first check.
const AllowLinkLocalEnv = "GATEON_ALLOW_LINK_LOCAL_TARGETS"

// allowLinkLocal reports whether AllowLinkLocalEnv is set. A variable rather
// than a function so a test can set it.
var allowLinkLocal = sync.OnceValue(func() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(AllowLinkLocalEnv))) {
	case "1", "true", "yes":
		return true
	}
	return false
})
