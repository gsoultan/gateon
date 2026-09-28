// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"
)

// An operator's block held until it was released; only an automatic shun set
// expires_at (ADR 0031). A manual block may now carry an optional duration and
// lapse on its own, chosen by the operator rather than the ladder (ADR 0037).
// It reuses the expires_at column migration 66 added -- no migration this
// round.

// TestAManualBlockWithADurationLapsesWithoutAnOperator: a block written with a
// duration is enforced, and lifts the moment its expires_at passes with nothing
// sweeping the row and no operator releasing it -- the same path an automatic
// shun lapses through.
func TestAManualBlockWithADurationLapsesWithoutAnOperator(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const ip = "198.51.100.150"
		if err := MarkIPMitigatedFor(ip, "manual, 30m", 30*time.Minute); err != nil {
			t.Fatalf("mark a bounded manual block: %v", err)
		}
		if !IsIPMitigated(ip) {
			t.Fatalf("a manual block just written with a 30m duration does not refuse %s", ip)
		}

		// The expiry round-trips through the store: a bounded manual block
		// stores its end, not the NULL an open-ended block keeps.
		row, err := getStore().readIPShun(ip)
		if err != nil {
			t.Fatalf("read the block back: %v", err)
		}
		if !row.expiresAt.Valid {
			t.Fatal("a manual block written with a duration has no expires_at; it would never lapse")
		}
		if got := row.expiresAt.Time.Sub(row.mitigatedAt.Time); got < 29*time.Minute || got > 31*time.Minute {
			t.Errorf("the stored block lasts %v, not the 30m requested", got)
		}

		// Move it past its end. Nothing else touches the row; enforcement reads
		// the end and the list stops counting it.
		ageIPShun(t, ip, 31*time.Minute)
		if IsIPMitigated(ip) {
			t.Errorf("a manual block whose duration elapsed still refuses %s: it needs an operator to lift, "+
				"so the optional duration did nothing", ip)
		}
		if _, total := GetIPMitigations(t.Context(), 50, 0); total != 0 {
			t.Errorf("the mitigation list still counts %d block(s) after the duration elapsed", total)
		}
	})
}

// TestAManualBlockWithNoDurationNeverLapses: the behaviour before ADR 0037 is
// unchanged. An open-ended manual block keeps a NULL expires_at and holds
// however long the address has been quiet -- only an operator's release lifts
// it.
func TestAManualBlockWithNoDurationNeverLapses(t *testing.T) {
	onEachShunEngine(t, func(t *testing.T) {
		const ip = "198.51.100.151"
		if err := MarkIPMitigated(ip, "manual, open-ended"); err != nil {
			t.Fatalf("mark an open-ended manual block: %v", err)
		}
		row, err := getStore().readIPShun(ip)
		if err != nil {
			t.Fatalf("read the block back: %v", err)
		}
		if row.expiresAt.Valid {
			t.Fatalf("an open-ended manual block has an expires_at (%v); it would lapse on its own",
				row.expiresAt.Time)
		}

		// Two days later, with no operator involved, it still refuses the
		// address: ageIPShun cannot move a NULL end into the past.
		ageIPShun(t, ip, 48*time.Hour)
		if !IsIPMitigated(ip) {
			t.Errorf("an open-ended manual block written 48h ago no longer refuses %s: it lapsed with no "+
				"operator releasing it", ip)
		}
	})
}
