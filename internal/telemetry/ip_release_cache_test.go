// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// TestAutomaticIPShunAfterTheSourceHasBeenSeen is the regression test for a
// cache that read "not blocked" as "released by an operator".
//
// IsIPMitigated and IsIPUnmitigated share one cache of booleans, and do not
// agree on what the boolean means. IsIPUnmitigated stores whether the row says
// an operator released the address; IsIPMitigated stores whether the address is
// *not* blocked, which is also true of an address with no row at all. The IP
// block on every entrypoint asks IsIPMitigated on every request, so after one
// request from any address its entry read true -- and IsIPUnmitigated answered
// that the operator had released it.
//
// Every automatic IP block checks IsIPUnmitigated first, so that an operator's
// release is not overridden: the unique-fingerprint shun in escalateMitigation,
// the anomaly detector's shun and a playbook's block. An attacker's threats are
// recorded from requests that went through the IP block, so each of those found
// the attacker "released" and blocked nothing.
func TestAutomaticIPShunAfterTheSourceHasBeenSeen(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "release-cache.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(context.Background()) })

	const ip = "203.0.113.95"
	gate := identity.IPMitigation()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serve := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip + ":40500"
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		return rr.Code
	}

	// The attacker's traffic passes the IP block first, as every request does.
	if got := serve(); got != http.StatusOK {
		t.Fatalf("setup: a fresh address was refused: %d", got)
	}
	if telemetry.IsIPUnmitigated(ip) {
		t.Fatalf("%s was never released by anyone, and IsIPUnmitigated says it was", ip)
	}

	// Three distinct malicious fingerprints from one address is the point at
	// which escalateMitigation shuns the address itself.
	for i := range 3 {
		fp := fmt.Sprintf("t13d1516h2_release_cache_%d", i)
		t.Cleanup(func() { telemetry.ResetReputation(repid.For(fp, ip)) })
		telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
			Type: "waf_blocked", SourceIP: ip, Fingerprint: fp, Score: 100,
			Category: "sqli", Severity: "critical", ActionTaken: telemetry.ActionBlocked,
		})
	}
	telemetry.FlushThreats()

	if got := serve(); got != http.StatusForbidden {
		t.Fatalf("three malicious fingerprints from %s did not shun it: the next request got %d, want 403", ip, got)
	}
}
