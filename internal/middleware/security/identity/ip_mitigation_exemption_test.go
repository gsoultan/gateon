// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// ipMitigationStatus is the status IPMitigation answers a request from ip with.
func ipMitigationStatus(ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = net.JoinHostPort(ip, "41000")
	rr := httptest.NewRecorder()
	IPMitigation()(okOrigin()).ServeHTTP(rr, req)
	return rr.Code
}

// TestAnExemptAddressOnTheIPBlockListIsServed: IPMitigation refused an
// address on the IP mitigation list whatever GATEON_MITIGATION_ALLOWLIST said
// -- "never mitigated" -- and whether or not it was loopback, while the
// fingerprint and reputation blocks served both (ADR 0029 left it open). A TCP
// entrypoint now enforces the same list, and ADR 0032 has both paths ask one
// rule, AddressBlocked, so that they refuse the same clients.
func TestAnExemptAddressOnTheIPBlockListIsServed(t *testing.T) {
	scopeTestStore(t)
	const allowlisted, shunned = "203.0.113.170", "203.0.113.171"
	for _, ip := range []string{allowlisted, shunned, "127.0.0.1", "::1"} {
		if err := telemetry.MarkIPMitigated(ip, "test: on the IP mitigation list"); err != nil {
			t.Fatalf("shun %s: %v", ip, err)
		}
	}
	withAllowlist(t, allowlisted+"/32")

	if code := ipMitigationStatus(shunned); code != http.StatusForbidden {
		t.Fatalf("control: %s is on the list and not exempt, and got %d, want 403", shunned, code)
	}
	for _, ip := range []string{allowlisted, "127.0.0.1", "::1"} {
		if code := ipMitigationStatus(ip); code != http.StatusOK {
			t.Errorf("%s is on the list but exempt from enforcement, and got %d, want 200", ip, code)
		}
	}
}
