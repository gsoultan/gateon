// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// An operator's block of one IPv6 address is a block of its /64 (ADR 0058).
// For an allowlisted address the answer said the block was "recorded but not
// enforced ... still served", and named only the address, while every other
// address of the /64 was refused (review 3). The answer now says what the
// block covers, whether or not the address itself is exempt, and says nothing
// of the kind for IPv4, whose block is the address.
func TestAManualIPv6BlockSaysItCoversTheSlash64(t *testing.T) {
	mitigation.SetAllowlist([]netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::5/128")})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	for _, tc := range []struct {
		source, neighbour, reach string
		success                  bool
	}{
		{"2001:db8:1:2::5", "2001:db8:1:2::6", "2001:db8:1:2::/64", false},
		{"2001:db8:9:9::5", "2001:db8:9:9::6", "2001:db8:9:9::/64", true},
		{"203.0.113.44", "", "", true},
	} {
		t.Run(tc.source, func(t *testing.T) {
			svc, _, _, _ := applyFixService(t)
			resp, err := svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: tc.source})
			if err != nil || resp.GetSuccess() != tc.success {
				t.Fatalf("block %s: err=%v resp=%v, want success=%v", tc.source, err, resp, tc.success)
			}
			msg := resp.GetMessage()
			if tc.reach == "" {
				if strings.Contains(msg, "/64") {
					t.Errorf("an IPv4 block's answer speaks of a /64: %q", msg)
				}
				return
			}
			if !identity.AddressBlocked(tc.neighbour) {
				t.Fatalf("setup: %s, in the blocked /64, is served", tc.neighbour)
			}
			if !strings.Contains(msg, tc.reach) {
				t.Errorf("%s is refused, but the answer does not say the block covers %s: %q", tc.neighbour, tc.reach, msg)
			}
		})
	}
}
