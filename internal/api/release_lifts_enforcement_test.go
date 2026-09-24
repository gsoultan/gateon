// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// enforcementGate is the refusal stack every route carries, in router order:
// the IP block, the fingerprint block and the reputation blocker. A release is
// only a release if a request comes through all three afterwards.
func enforcementGate(t *testing.T) http.Handler {
	t.Helper()
	// The blocker declines to act under GATEON_TEST unless this is set.
	t.Setenv("GATEON_ENABLE_TEST_REPUTATION", "1")
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return identity.IPMitigation()(identity.UserMitigation()(identity.ReputationBlocker("release-test")(ok)))
}

// serveAsClient sends a request carrying the fingerprint and address the
// entrypoint would have resolved for this client.
func serveAsClient(h http.Handler, fingerprint, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/account", nil)
	req.RemoteAddr = ip + ":41000"
	req = req.WithContext(request.WithState(req.Context(), &request.RequestState{JA4Plus: fingerprint}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// earnRefusal records WAF blocks from one client through the real recording
// path -- the store's threat loop, which applies the reputation penalty -- until
// the gate refuses that client.
func earnRefusal(t *testing.T, gate http.Handler, fingerprint, ip string, blocks int) {
	t.Helper()
	for range blocks {
		telemetry.RecordSecurityThreat(telemetry.SecurityThreat{
			Type:        "waf_blocked",
			SourceIP:    ip,
			Fingerprint: fingerprint,
			Score:       100,
			Category:    "sqli",
			Severity:    "critical",
			ActionTaken: telemetry.ActionBlocked,
		})
	}
	telemetry.FlushThreats()
	if got := serveAsClient(gate, fingerprint, ip); got != http.StatusForbidden {
		t.Fatalf("setup: after %d WAF blocks the client got %d, want 403", blocks, got)
	}
}

// TestReleaseLiftsTheReputationBlock is the regression test for a release that
// reported success and left the client refused.
//
// Since ADR 0011 a reputation score lives under repid.For(fingerprint,
// network), and that composite is what the reputation blocker reads. The
// release path still reset the bare address and the bare fingerprint -- keys
// the recording path stopped writing when the identity was scoped -- so it
// removed nothing, answered "removed successfully", and the client stayed at
// score zero behind a 403 on every route until the score recovered on its own,
// hours later. The operator releasing a false positive was told it had worked.
func TestReleaseLiftsTheReputationBlock(t *testing.T) {
	_ = telemetry.ClosePathStatsStore(context.Background())
	telemetry.ResetFingerprintSightings()
	t.Cleanup(telemetry.ResetFingerprintSightings)

	t.Run("release by address", func(t *testing.T) {
		const fp, ip = "t13d1516h2_release_by_address_a1_b2", "203.0.113.41"
		svc := newMitigationTestService(t)
		gate := enforcementGate(t)
		t.Cleanup(func() { telemetry.ResetReputation(repid.For(fp, ip)) })

		// Two blocks: enough to drive the score to zero, not enough for the
		// fingerprint block, so the reputation blocker is the only refusal.
		earnRefusal(t, gate, fp, ip, 2)

		res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{Source: ip})
		if err != nil || !res.GetSuccess() {
			t.Fatalf("release failed: err=%v msg=%q", err, res.GetMessage())
		}
		if got := serveAsClient(gate, fp, ip); got != http.StatusOK {
			t.Fatalf("after %q the released client still gets %d; the reputation "+
				"block survived a release the operator was told had worked", res.GetMessage(), got)
		}
	})

	t.Run("release by fingerprint", func(t *testing.T) {
		const fp, ip = "t13d1516h2_release_by_fingerprint_c3_d4", "198.51.100.42"
		svc := newMitigationTestService(t)
		gate := enforcementGate(t)
		t.Cleanup(func() { telemetry.ResetReputation(repid.For(fp, ip)) })

		// Three blocks: the fingerprint is blocked as well, which is what gives
		// the fingerprint release something to release.
		earnRefusal(t, gate, fp, ip, 3)
		if !telemetry.IsUserMitigated(fp) {
			t.Fatal("setup: three blocks from one address did not mitigate the fingerprint")
		}

		res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{
			Source: fp, Ja4Plus: fp,
		})
		if err != nil || !res.GetSuccess() {
			t.Fatalf("release failed: err=%v msg=%q", err, res.GetMessage())
		}
		if got := serveAsClient(gate, fp, ip); got != http.StatusOK {
			t.Fatalf("after %q the released client still gets %d; the fingerprint "+
				"release lifted the fingerprint block and left its reputation block", res.GetMessage(), got)
		}
	})
}
