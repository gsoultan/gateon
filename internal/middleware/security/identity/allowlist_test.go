// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"
	"testing"

	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// withAllowlist installs an allowlist for the duration of a test.
func withAllowlist(t *testing.T, cidrs string) {
	t.Helper()
	mitigation.SetAllowlist(mitigation.ParseAllowlist(cidrs))
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })
}

// okOrigin is a backend that always succeeds, so a test asserting a
// middleware refused a request is measuring the middleware rather than the
// origin. Three lines per package beats exporting a test double across a
// package boundary.
func okOrigin() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// TestAllowlistedSourceIsNotRefusedByReputation covers the 403.
func TestAllowlistedSourceIsNotRefusedByReputation(t *testing.T) {
	const browser = "t13d1516h2_8daaf6152771_b0da82dd1658_allowlist"
	client := repTestClient{ja4Plus: browser, remoteIP: "203.0.113.90"}

	// Earn a score of zero the way the threat pipeline would.
	telemetry.DecreaseReputation(
		repid.For(client.ja4Plus, client.remoteIP),
		99, "test: allowlisted source with a bad score")

	h := blockerHandler(t)

	if got := serveWithIdentity(h, client); got != http.StatusForbidden {
		t.Fatalf("without an allowlist the client got %d, want 403 — the rest of "+
			"this test would prove nothing", got)
	}

	withAllowlist(t, "203.0.113.0/24")
	if got := serveWithIdentity(h, client); got != http.StatusOK {
		t.Errorf("an allowlisted source got %d, want 200.\n"+
			"GATEON_MITIGATION_ALLOWLIST says these sources are never mitigated, and "+
			"a 403 from the reputation blocker is the most common way gateon "+
			"mitigates anything.", got)
	}
}
