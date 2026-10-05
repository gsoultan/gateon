// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// fixFingerprint is one stock browser build's JA4+: shared by every client
// running it, which is why a block on it is a block on bystanders.
const fixFingerprint = "t13d1516h2_8daaf6152771_e5627efa2ab1"

// recordFixThreat records a fingerprinted brute-force finding from ip, as the
// anomaly engine does, and returns its id.
func recordFixThreat(t *testing.T, id, ip string) string {
	t.Helper()
	telemetry.RecordSecurityThreat(telemetry.SecurityThreat{ID: id, Type: findingBruteForce, SourceIP: ip,
		Fingerprint: fixFingerprint, Category: "auth"})
	telemetry.FlushThreats()
	if _, err := telemetry.GetSecurityThreatByID(t.Context(), id); err != nil {
		t.Fatalf("threat %s not stored, so the fix has nothing to read: %v", id, err)
	}
	return id
}

// mitigationRows counts the address and fingerprint blocks in force.
func mitigationRows(t *testing.T) (ips, fingerprints int) {
	t.Helper()
	_, ips = telemetry.GetIPMitigations(t.Context(), 100, 0)
	_, fingerprints = telemetry.GetUserMitigations(t.Context(), 100, 0)
	return ips, fingerprints
}

// TestApplyFixRefusesAnExemptSourceBeforeWritingAnything is review-3 F2 and
// F3. Apply fix on a brute-force finding blocked the finding's fingerprint on
// the source's /24 with no expiry and no exemption check, then wrote the
// address block, and only then found the address exempt and answered "not
// enforced ... still served". For an allowlisted IPv6 source that block is
// keyed to the /64 and the exemption spares only the address itself, so the
// rest of its network was refused for 24 hours under an answer that said
// nothing had happened. An exempt source is now refused before anything is
// written: no address row, no fingerprint row.
func TestApplyFixRefusesAnExemptSourceBeforeWritingAnything(t *testing.T) {
	mitigation.SetAllowlist([]netip.Prefix{
		netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("2001:db8:1:2::5/128"),
	})
	t.Cleanup(func() { mitigation.SetAllowlist(nil) })

	for _, tc := range []struct{ source, neighbour, why string }{
		{"198.51.100.7", "198.51.100.8", "GATEON_MITIGATION_ALLOWLIST"},
		{"2001:db8:1:2::5", "2001:db8:1:2::6", "GATEON_MITIGATION_ALLOWLIST"},
		{"127.0.0.1", "127.0.0.2", "loopback"},
	} {
		t.Run(tc.source, func(t *testing.T) {
			svc, _, _, _ := applyFixService(t)
			threat := recordFixThreat(t, "th-exempt-"+tc.source, tc.source)
			if ips, fps := mitigationRows(t); ips != 0 || fps != 0 {
				t.Fatalf("before the fix: %d address and %d fingerprint blocks, want none", ips, fps)
			}
			resp, err := svc.ApplyRecommendation(t.Context(), &gateonv1.ApplyRecommendationRequest{
				AnomalyType: findingBruteForce, Source: tc.source, ThreatId: threat})
			if err != nil || resp.GetSuccess() {
				t.Fatalf("apply fix on exempt %s: err=%v resp=%v, want a refusal", tc.source, err, resp)
			}
			if msg := resp.GetMessage(); !strings.Contains(msg, "nothing was written") || !strings.Contains(msg, tc.why) {
				t.Errorf("refusal does not say nothing was written, and why (%s): %q", tc.why, msg)
			}
			if ips, fps := mitigationRows(t); ips != 0 || fps != 0 {
				t.Errorf("after the refused fix: %d address and %d fingerprint blocks, want none", ips, fps)
			}
			if identity.AddressBlocked(tc.neighbour) {
				t.Errorf("%s, a neighbour of the exempt source, is refused after a fix that reported failure", tc.neighbour)
			}
			if telemetry.IsUserMitigated(repid.For(fixFingerprint, tc.neighbour)) {
				t.Errorf("the source's browser class is blocked on its network")
			}
		})
	}
}

// TestApplyFixBlocksTheSourceAndNotItsBrowserClass is the rest of F2: for a
// source the fix may block, it writes the one 24-hour block-list entry ADR
// 0063 describes, and no block on the source's browser class -- that names
// every client of one browser build on its network, not the source the
// finding names, and it never expired.
func TestApplyFixBlocksTheSourceAndNotItsBrowserClass(t *testing.T) {
	svc, _, _, _ := applyFixService(t)
	const ip = "203.0.113.9"
	threat := recordFixThreat(t, "th-block", ip)
	if ips, fps := mitigationRows(t); ips != 0 || fps != 0 {
		t.Fatalf("before the fix: %d address and %d fingerprint blocks, want none", ips, fps)
	}
	resp, err := svc.ApplyRecommendation(t.Context(), &gateonv1.ApplyRecommendationRequest{
		AnomalyType: findingBruteForce, Source: ip, ThreatId: threat})
	if err != nil || !resp.GetSuccess() {
		t.Fatalf("apply fix: err=%v resp=%v", err, resp)
	}
	ips, fps := mitigationRows(t)
	if ips != 1 || fps != 0 {
		t.Fatalf("after the fix: %d address and %d fingerprint blocks, want exactly one address block", ips, fps)
	}
	assertBlockExpiresWithin(t, ip, recommendationBlockDuration)
	if telemetry.IsUserMitigated(repid.For(fixFingerprint, "203.0.113.10")) {
		t.Error("the source's browser class is blocked on its network")
	}
	if msg := resp.GetMessage(); !strings.Contains(msg, recommendationBlockWords) || strings.Contains(strings.ToLower(msg), "fingerprint") {
		t.Errorf("message does not describe exactly what was written: %q", msg)
	}
}
