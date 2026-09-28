// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package challenge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// The challenge half of the GATEON_MITIGATION_ALLOWLIST tests. The rest --
// the honeypot ban, the observation boundary, the default and the address
// forms -- stayed in package security's allowlist_test.go, and the reputation
// and mitigation cases are in package identity's. Split along ADR-0030's
// boundary so each test sits with the code it drives.

// withAllowlist installs an allowlist for the duration of a test. The same
// three lines exist in security and identity; a test helper is not worth an
// exported symbol across a package boundary.
func withAllowlist(t *testing.T, cidrs string) {
	t.Helper()
	mitigation.SetAllowlist(mitigation.ParseAllowlist(cidrs))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
}

// TestAllowlistedSourceIsNotChallengedByProofOfWork covers the challenge.
//
// A proof-of-work challenge costs the client a round trip and CPU, and an API
// client or a monitoring probe cannot solve one at all — so for a non-browser
// source this is indistinguishable from a block.
func TestAllowlistedSourceIsNotChallengedByProofOfWork(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658_pow"
	const ip = "203.0.113.7"

	// The challenge only fires below the reputation threshold, so the source has
	// to have earned a bad score first. Without this the test would pass whether
	// or not the allowlist is consulted, which is the most common way an
	// exemption test proves nothing.
	telemetry.DecreaseReputation(repid.For(browser, ip), 99, "test: pow")

	serve := func() (bool, int) {
		reached := false
		h := Pow(1, 50, "test-secret", "allowlist-test")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		req.RemoteAddr = ip + ":51234"
		req = req.WithContext(context.WithValue(req.Context(),
			request.RequestStateContextKey{}, &request.RequestState{JA4Plus: browser}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return reached, rr.Code
	}

	if reached, code := serve(); reached {
		t.Fatalf("the source was not challenged without an allowlist (status %d); "+
			"the rest of this test would prove nothing", code)
	}

	withAllowlist(t, "203.0.113.0/24")
	if reached, code := serve(); !reached {
		t.Errorf("an allowlisted source was challenged (status %d); a monitoring "+
			"probe or an API client cannot solve a proof-of-work challenge, so for "+
			"it this is indistinguishable from a block", code)
	}
}
