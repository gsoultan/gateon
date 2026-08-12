// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestUserMitigation(t *testing.T) {
	// Initialize store
	dbPath := filepath.Join(t.TempDir(), "gateon_user_mit_test.db")

	_ = InitPathStatsStore(dbPath, 1)
	defer ClosePathStatsStore(context.Background())

	ja4_1 := "test-ja4-1"
	ja4_2 := "test-ja4-2"
	ja4h := "test-ja4h"

	// 1. Initially should not be mitigated
	if IsUserMitigated(ja4_1) {
		t.Error("Expected user to not be mitigated initially")
	}

	// 2. Mitigate JA4 1
	MarkUserMitigated(ja4_1, "JA4", "Test reasoning", "TestCategory")

	// 3. Should now be mitigated
	if !IsUserMitigated(ja4_1) {
		t.Error("Expected JA4 1 to be mitigated")
	}

	// 4. Unmitigate JA4 1
	MarkUserUnmitigated(ja4_1)

	// 5. Should immediately be unmitigated (cache test)
	if IsUserMitigated(ja4_1) {
		t.Error("Expected JA4 1 to be unmitigated immediately")
	}

	// 6. Mitigate JA4 2
	MarkUserMitigated(ja4_2, "JA4", "Test reasoning JA4", "TestCategory")

	// 7. Should now be mitigated
	if !IsUserMitigated(ja4_2) {
		t.Error("Expected JA4 2 to be mitigated")
	}

	// 8. Test JA4+JA4H composite
	ja4plus := ja4_2 + "_" + ja4h
	if IsUserMitigated(ja4plus) {
		t.Error("Expected other JA4 combo to not be mitigated")
	}

	MarkUserMitigated(ja4plus, "JA4", "Test reasoning JA4+JA4H", "TestCategory")
	if !IsUserMitigated(ja4plus) {
		t.Error("Expected JA4+JA4H to be mitigated")
	}
}

func TestIPEscalation(t *testing.T) {
	// Initialize store
	dbPath := filepath.Join(t.TempDir(), "gateon_ip_esc_test.db")

	_ = InitPathStatsStore(dbPath, 1)
	defer ClosePathStatsStore(context.Background())

	ip := "1.1.1.1"

	// 1. Record 3 threats with different fingerprints from same IP
	for i := 1; i <= 3; i++ {
		st := SecurityThreat{
			SourceIP:    ip,
			Fingerprint: "user-" + string(rune('0'+i)),
			Score:       100,
			ActionTaken: "blocked",
		}
		RecordSecurityThreat(st)
	}

	// Wait for background worker to process threats and escalate to IP mitigation
	time.Sleep(200 * time.Millisecond)

	// 2. Check if IP is now mitigated
	if !IsIPMitigated(ip) {
		t.Error("Expected IP to be escalated to mitigation after 3 unique malicious users")
	}
}

// A release applied in the same second as the block it undoes must win.
//
// user_mitigations rows are timestamped with CURRENT_TIMESTAMP, which is
// second-granular on SQLite, so a mitigate immediately followed by an
// unmitigate produces two rows the ORDER BY cannot separate. With updated_at as
// the only sort key the winner was whatever the storage engine happened to
// return, and when the stale row won, remove-mitigation reported success while
// the client stayed blocked — the failure an operator can neither diagnose nor
// work around.
//
// This is the ordinary case, not a corner: an operator clears a threat that has
// just fired, and the e2e suite releases what it has just earned.
//
// Against the pre-fix query this fails whenever the tie resolves to the
// mitigated row.
func TestUnmitigationWinsSameSecondTie(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gateon_tie_test.db")
	_ = InitPathStatsStore(dbPath, 1)
	defer ClosePathStatsStore(context.Background())

	// A fresh fingerprint each pass: MarkUserUnmitigated deliberately suppresses
	// re-mitigation of the same fingerprint for 24h, so reusing one would test
	// that suppression rather than the tie-break.
	for i := range 10 {
		fp := "tie-ja4plus-" + strconv.Itoa(i)
		MarkUserMitigated(fp, "JA4+", "blocked", "waf")
		if !IsUserMitigated(fp) {
			t.Fatalf("iteration %d: fingerprint not mitigated after MarkUserMitigated", i)
		}

		// No sleep: the point is that both rows land in the same second.
		MarkUserUnmitigated(fp)
		if IsUserMitigated(fp) {
			t.Fatalf("iteration %d: still mitigated after release applied in the same "+
				"second; the operator was told it worked", i)
		}
	}
}

// And the release must keep holding once the second rolls over, so the fix is a
// tie-break rather than an ordering accident.
func TestUnmitigationHoldsAcrossSecondBoundary(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gateon_hold_test.db")
	_ = InitPathStatsStore(dbPath, 1)
	defer ClosePathStatsStore(context.Background())

	const fp = "hold-ja4plus"

	MarkUserMitigated(fp, "JA4+", "blocked", "waf")
	MarkUserUnmitigated(fp)
	time.Sleep(1100 * time.Millisecond)

	if IsUserMitigated(fp) {
		t.Error("mitigation returned after the release, once timestamps differed")
	}
	if !IsUserUnmitigated(fp) {
		t.Error("release marker not visible to processThreat; the next blocked " +
			"request would re-apply the mitigation immediately")
	}
}
