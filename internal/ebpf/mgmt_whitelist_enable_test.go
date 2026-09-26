// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ebpf

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestSeedManagementWhitelistRefusesToEnableAgainstAnEmptyAllowlist is the
// lockout guard.
//
// Both programs read mgmt_whitelist as "if the allowlist is on, a packet to the
// management port whose source is not in the map is dropped". The map is an
// exact-match IPv4 hash. So turning the flag on with nothing installed drops
// every management packet at the NIC, and the only way back is detaching the
// program -- which needs the access that was just refused.
//
// That is reachable by ordinary misconfiguration, not by malice:
// ManagementConfig.AllowedIps, the list an operator would reach for, defaults
// to 0.0.0.0/0 and ::/0, and a CIDR cannot be encoded as either map's key. So
// the count of what actually reached the kernel, not the operator's intent, is
// what may switch the branch on.
func TestSeedManagementWhitelistRefusesToEnableAgainstAnEmptyAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []string
	}{
		{"nothing configured", nil},
		{"the management default, which is a CIDR", []string{"0.0.0.0/0", "::/0"}},
		{"not an address at all", []string{"admin.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewEbpfManager(&gateonv1.EbpfConfig{
				Enabled:             true,
				MgmtPort:            8443,
				EnableMgmtWhitelist: true,
				MgmtWhitelistIps:    tc.ips,
			})

			if installed := m.seedManagementWhitelist(); installed != 0 {
				t.Errorf("seedManagementWhitelist installed %d address(es) from %v; "+
					"want 0, which is what keeps the kernel branch off", installed, tc.ips)
			}
		})
	}
}

// TestSeedManagementWhitelistIsOffWhenNotAskedFor pins that the count is zero
// when the operator never enabled it, so the flag cannot be written on the
// strength of addresses left in the config from a previous experiment.
func TestSeedManagementWhitelistIsOffWhenNotAskedFor(t *testing.T) {
	m := NewEbpfManager(&gateonv1.EbpfConfig{
		Enabled:             true,
		MgmtPort:            8443,
		EnableMgmtWhitelist: false,
		MgmtWhitelistIps:    []string{"203.0.113.7"},
	})

	if installed := m.seedManagementWhitelist(); installed != 0 {
		t.Errorf("seedManagementWhitelist installed %d address(es) with the feature off; want 0", installed)
	}
}

// TestWhitelistKeysTakesOnlyWhatTheMapCanExpress covers the encoder directly:
// an unencodable entry must be skipped, not approximated. Widening a /24 to
// its network address would admit an address the operator did not name, and
// narrowing it would lock out ones they did. A bare IPv6 address is exact, and
// goes to the IPv6 map.
func TestWhitelistKeysTakesOnlyWhatTheMapCanExpress(t *testing.T) {
	keys := whitelistKeys([]string{
		"203.0.113.7",     // kept
		"198.51.100.0/24", // CIDR: no
		"2001:db8::/64",   // CIDR: no
		"2001:db8::1",     // IPv6: kept, in the IPv6 map
		"",                // empty: no
		"203.0.113.7",     // duplicate of the first
	})

	if len(keys.v4) != 1 || len(keys.v6) != 1 {
		t.Fatalf("whitelistKeys returned %d IPv4 and %d IPv6 key(s), want exactly one of each",
			len(keys.v4), len(keys.v6))
	}
	want, err := ipToUint32("203.0.113.7")
	if err != nil {
		t.Fatalf("ipToUint32: %v", err)
	}
	if _, ok := keys.v4[want]; !ok {
		t.Error("the one bare IPv4 address configured is not among the keys")
	}
}
