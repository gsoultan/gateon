// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
)

// A reputation identity is never named by a header the client writes
// (dataplane F10, ADR 0058). GetIPFingerprint fell back to the leftmost
// X-Forwarded-For, read raw, as the class half of the identity. The fallback
// was not reachable while GenerateJA4H always answers -- so the gate that
// failed against it is check-security-invariants.sh's forwarding-header
// check -- and this pins the property through the public path: the same
// request from an untrusted peer has one identity whatever it claims to have
// been forwarded for.
func TestAForwardingHeaderFromAnUntrustedPeerNeverNamesTheReputationIdentity(t *testing.T) {
	const peer, claimed = "198.51.100.7", "203.0.113.99"
	build := func(withState bool, header string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = peer + ":40000"
		if header != "" {
			r.Header.Set(header, claimed)
		}
		if withState {
			r = r.WithContext(request.WithState(r.Context(), &request.RequestState{}))
		}
		return r
	}
	for _, withState := range []bool{false, true} {
		plain := GetReputationID(build(withState, ""))
		for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
			got := GetReputationID(build(withState, h))
			if got != plain {
				t.Errorf("state=%v, %s: identity %q, want %q as without the header", withState, h, got, plain)
			}
			if strings.Contains(got, claimed) || strings.Contains(GetIPFingerprint(build(withState, h)), claimed) {
				t.Errorf("state=%v, %s: the identity carries the address the client claimed: %q", withState, h, got)
			}
		}
		if !strings.HasSuffix(plain, "|198.51.100") {
			t.Errorf("state=%v: identity %q is not scoped to the peer's network", withState, plain)
		}
	}
}
