// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// IPMitigation refuses an IPv6 client by its /64 (ADR 0058): a block of one
// address reaches the host behind it whichever address of its /64 it uses
// next, through the real middleware. The allowlist is still read for the
// address that asks, so an allowlisted address inside a blocked /64 is served.
func TestIPMitigationRefusesTheWholeSlashSixtyFourButNotAnAllowlistedAddress(t *testing.T) {
	scopeTestStore(t)
	const allowlisted = "2001:db8:44:1::a"
	withAllowlist(t, allowlisted+"/128")
	if err := telemetry.MarkIPMitigated("2001:db8:44:1::1", "test"); err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]int{
		"2001:db8:44:1::1":                  http.StatusForbidden,
		"2001:db8:44:1:9999:8888:7777:6666": http.StatusForbidden,
		allowlisted:                         http.StatusOK,
		"2001:db8:44:2::1":                  http.StatusOK,
	} {
		if got := ipMitigationStatus(ip); got != want {
			t.Errorf("%s: got %d, want %d", ip, got, want)
		}
	}
}
