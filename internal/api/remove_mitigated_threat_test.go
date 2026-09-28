// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Fingerprint releases used to report success for an operation that may have
// removed nothing.
//
// RemoveMitigatedThreat rebuilt source+"_"+ja4h for clients too old to send
// ja4plus, which was a guess at the key a block was filed under: when the guess
// matched no row, nothing was released, and the handler returned Success
// anyway. The operator clicks "Allow", is told the source is released, and the
// client stays blocked.
//
// Blocks are now a class on a network (repid.For, ADR 0026), and a release
// that names a fingerprint finds them by the class, whichever of the
// fingerprint's shapes it is named by; these keep it honest about what it
// released.
func TestRemoveMitigatedThreatReportsWhatItReleased(t *testing.T) {
	const (
		ja4  = "t13d1516h2_8daaf6152771_b186095e22b6"
		ja4h = "ge11nn0200_7e33b58890ac"
		ip   = "203.0.113.7"
	)
	blocked := repid.For(ja4+"_"+ja4h, ip)

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

		// A legacy client sends ja4h but no ja4plus, and nothing is blocked for
		// the class they name.
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

	t.Run("a legacy request releases the class it names", func(t *testing.T) {
		svc := newMitigationTestService(t)

		// The block is filed under the class on the client's network. The
		// legacy request carries the JA4 and the JA4H apart, which name the
		// same class.
		telemetry.MarkUserMitigated(blocked, "JA4+", "blocked", "waf")
		if !telemetry.IsUserMitigated(blocked) {
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
		if telemetry.IsUserMitigated(blocked) {
			t.Fatal("still mitigated after a release the operator was told had worked")
		}
	})

	t.Run("explicit ja4plus is released", func(t *testing.T) {
		svc := newMitigationTestService(t)

		telemetry.MarkUserMitigated(blocked, "JA4+", "blocked", "waf")
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
		if telemetry.IsUserMitigated(blocked) {
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
	key := repid.For(ja4, "203.0.113.7")
	svc := newMitigationTestService(t)

	res, err := svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: ja4 + "|203.0.113.7"})
	if err != nil {
		t.Fatalf("MitigateThreat returned an error: %v", err)
	}
	if !res.GetSuccess() {
		t.Fatalf("a fresh fingerprint was not mitigated: %q", res.GetMessage())
	}

	telemetry.MarkUserUnmitigated(key)

	res, err = svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: ja4 + "|203.0.113.7"})
	if err != nil {
		t.Fatalf("MitigateThreat returned an error: %v", err)
	}
	if res.GetSuccess() && !telemetry.IsUserMitigated(key) {
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
