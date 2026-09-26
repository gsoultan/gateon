// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// TestMitigationAllowlistReachesTheRequestPath is the regression test for an
// allowlist that only one component ever received.
//
// GATEON_MITIGATION_ALLOWLIST is documented as covering the whole gateway --
// the reputation blocker, the honeypot, the tarpit and proof-of-work all
// consult mitigation.IsAllowlisted -- and the change that moved it there said
// it "is published once at startup". Nothing published it: SetAllowlist had
// no caller outside tests, so IsAllowlisted answered false for every address
// and only the correlated-incident responder, which parses its own copy, ever
// honoured the setting. An operator who allowlisted their office egress was
// still refused.
//
// The startup path is driven for real, and the enforcement is asserted on the
// middleware that carries the check. The non-allowlisted client with the same
// score is what shows the blocker would otherwise have refused.
func TestMitigationAllowlistReachesTheRequestPath(t *testing.T) {
	t.Setenv(envMitigationAllowlist, "203.0.113.0/24")
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startThreatPipeline(ctx, "test", nil)

	const browser = "t13d1516h2_allowlist_reaches_request_path"
	allowlisted, stranger := "203.0.113.7", "198.51.100.7"
	for _, ip := range []string{allowlisted, stranger} {
		id := repid.For(browser, ip)
		telemetry.DecreaseReputation(id, 200, "test: score driven to zero")
		t.Cleanup(func() { telemetry.ResetReputation(id) })
	}

	blocker := identity.ReputationBlocker("allowlist-test")(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	serve := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":40100"
		req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: browser}))
		rr := httptest.NewRecorder()
		blocker.ServeHTTP(rr, req)
		return rr.Code
	}

	if got := serve(stranger); got != http.StatusForbidden {
		t.Fatalf("setup: a client outside the allowlist with score zero got %d, want 403", got)
	}
	if got := serve(allowlisted); got != http.StatusOK {
		t.Fatalf("a client inside GATEON_MITIGATION_ALLOWLIST got %d, want 200: the setting "+
			"was read at startup and never reached the request path", got)
	}
}
