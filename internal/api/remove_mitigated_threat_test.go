// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Fingerprint releases used to report success for an operation that may have
// removed nothing.
//
// MarkUserMitigated stores the fingerprint string it is handed verbatim in
// user_mitigations.fingerprint, so the only keys that exist are ones some
// caller chose. RemoveMitigatedThreat rebuilt source+"_"+ja4h for clients too
// old to send ja4plus, which is a guess at that choice: when the block was
// filed under the plain fingerprint the guess matched no row, nothing was
// released, and the handler returned Success anyway. The operator clicks
// "Allow", is told the source is released, and the client stays blocked.
//
// Against the pre-fix handler the first two subtests fail on Success being
// true, and the guessed-key subtest additionally fails on the fingerprint
// still being mitigated afterwards.
func TestRemoveMitigatedThreatReportsWhatItReleased(t *testing.T) {
	const (
		ja4  = "t13d1516h2_8daaf6152771_b186095e22b6"
		ja4h = "ge11nn09enus"
	)

	t.Run("never mitigated is not a success", func(t *testing.T) {
		svc := newMitigationTestService(t)

		res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{
			Source: ja4,
		})
		if err != nil {
			t.Fatalf("RemoveMitigatedThreat returned an error: %v", err)
		}
		if res.GetSuccess() {
			t.Fatalf("released a fingerprint that was never mitigated and reported success: %q",
				res.GetMessage())
		}
	})

	t.Run("unresolvable legacy key is not a success", func(t *testing.T) {
		svc := newMitigationTestService(t)

		// A legacy client sends ja4h but no ja4plus, and nothing is filed under
		// either the plain fingerprint or the composite.
		res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{
			Source: ja4,
			Ja4H:   ja4h,
		})
		if err != nil {
			t.Fatalf("RemoveMitigatedThreat returned an error: %v", err)
		}
		if res.GetSuccess() {
			t.Fatalf("reported success for a key that resolves to no mitigation: %q",
				res.GetMessage())
		}
	})

	t.Run("guessed key must not masquerade as a release", func(t *testing.T) {
		svc := newMitigationTestService(t)

		// The block is filed under the plain fingerprint, which is what
		// MitigateThreat writes. The legacy request carries ja4h, so the old
		// code looked for ja4+"_"+ja4h and found nothing.
		telemetry.MarkUserMitigated(ja4, "JA4+", "blocked", "waf")
		if !telemetry.IsUserMitigated(ja4) {
			t.Fatal("setup: fingerprint not mitigated after MarkUserMitigated")
		}

		res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{
			Source: ja4,
			Ja4H:   ja4h,
		})
		if err != nil {
			t.Fatalf("RemoveMitigatedThreat returned an error: %v", err)
		}
		if !res.GetSuccess() {
			t.Fatalf("an in-force mitigation was not released: %q", res.GetMessage())
		}
		if telemetry.IsUserMitigated(ja4) {
			t.Fatal("still mitigated after a release the operator was told had worked")
		}
	})

	t.Run("legacy composite key is still released", func(t *testing.T) {
		svc := newMitigationTestService(t)

		// The other shape a caller writes: ja4+"_"+ja4h, used when a threat
		// carries no fingerprint of its own. This one the legacy path could
		// reach, and it must keep working.
		composite := ja4 + "_" + ja4h
		telemetry.MarkUserMitigated(composite, "JA4+", "blocked", "waf")
		if !telemetry.IsUserMitigated(composite) {
			t.Fatal("setup: composite not mitigated after MarkUserMitigated")
		}

		res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{
			Source: ja4,
			Ja4H:   ja4h,
		})
		if err != nil {
			t.Fatalf("RemoveMitigatedThreat returned an error: %v", err)
		}
		if !res.GetSuccess() {
			t.Fatalf("legacy composite release regressed: %q", res.GetMessage())
		}
		if telemetry.IsUserMitigated(composite) {
			t.Fatal("composite still mitigated after a successful release")
		}
	})

	t.Run("explicit ja4plus is released", func(t *testing.T) {
		svc := newMitigationTestService(t)

		telemetry.MarkUserMitigated(ja4, "JA4+", "blocked", "waf")
		res, err := svc.RemoveMitigatedThreat(t.Context(), &gateonv1.RemoveMitigatedThreatRequest{
			Source:  ja4,
			Ja4Plus: ja4,
			Ja4H:    ja4h,
		})
		if err != nil {
			t.Fatalf("RemoveMitigatedThreat returned an error: %v", err)
		}
		if !res.GetSuccess() {
			t.Fatalf("a mitigation named by the client was not released: %q", res.GetMessage())
		}
		if telemetry.IsUserMitigated(ja4) {
			t.Fatal("still mitigated after an explicit ja4plus release")
		}
	})
}

// MitigateThreat carried the same unconditional-success shape: it reported the
// source contained without ever asking whether the block took. A fingerprint
// inside its 24h release hold is the case that bites, because the row is
// written and the request path still lets the client through.
func TestMitigateThreatReportsWhetherTheBlockTook(t *testing.T) {
	const ja4 = "t13d1516h2_held_fingerprint"
	svc := newMitigationTestService(t)

	res, err := svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: ja4})
	if err != nil {
		t.Fatalf("MitigateThreat returned an error: %v", err)
	}
	if !res.GetSuccess() {
		t.Fatalf("a fresh fingerprint was not mitigated: %q", res.GetMessage())
	}

	telemetry.MarkUserUnmitigated(ja4)

	res, err = svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: ja4})
	if err != nil {
		t.Fatalf("MitigateThreat returned an error: %v", err)
	}
	if res.GetSuccess() && !telemetry.IsUserMitigated(ja4) {
		t.Fatalf("reported %q while the source is not blocked", res.GetMessage())
	}
}

// newMitigationTestService stands up a telemetry store in a temp dir and an
// ApiService over throwaway registries, and tears both down with the test.
func newMitigationTestService(t *testing.T) *ApiService {
	t.Helper()

	tmpDir := t.TempDir()
	if err := telemetry.InitPathStatsStore(filepath.Join(tmpDir, "telemetry.db"), 1); err != nil {
		t.Fatalf("InitPathStatsStore: %v", err)
	}
	t.Cleanup(func() {
		_ = telemetry.ClosePathStatsStore(context.Background())
	})

	return NewApiService(ApiServiceConfig{
		Middlewares: config.NewMiddlewareRegistry(filepath.Join(tmpDir, "middlewares.json")),
		Routes:      config.NewRouteRegistry(filepath.Join(tmpDir, "routes.json")),
	})
}
