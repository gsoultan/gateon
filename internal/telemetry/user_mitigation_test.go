// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"strconv"
	"testing"
	"time"
)

// Keys are a class on a network, as repid.For builds them (ADR 0026); the
// store neither writes nor enforces one without the network.
func TestUserMitigation(t *testing.T) {
	// Initialize store
	freshStore(t)

	ja4_1 := "test-ja4-1|203.0.113"
	ja4_2 := "test-ja4-2|203.0.113"
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

// The escalation of attack evidence to an IP shun is pinned in
// address_shun_test.go (ADR 0029).

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
	freshStore(t)

	// A fresh fingerprint each pass: MarkUserUnmitigated deliberately suppresses
	// re-mitigation of the same fingerprint for 24h, so reusing one would test
	// that suppression rather than the tie-break.
	for i := range 10 {
		fp := "tie-ja4plus-" + strconv.Itoa(i) + "|203.0.113"
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
	freshStore(t)

	const fp = "hold-ja4plus|203.0.113"

	MarkUserMitigated(fp, "JA4+", "blocked", "waf")
	MarkUserUnmitigated(fp)

	// The sleep is the point of the test -- the release and the block must end
	// up in different seconds, so the tie-break is exercised rather than the
	// ordering accident. What follows it is a poll rather than a second bet:
	// writes here are buffered and flushed on an interval (2s at the standard
	// tier), so a single check 1.1s later is a race this test lost about one
	// run in ten under -shuffle=on, and never in CI's declaration order.
	time.Sleep(1100 * time.Millisecond)

	if IsUserMitigated(fp) {
		t.Error("mitigation returned after the release, once timestamps differed")
	}

	deadline := time.Now().Add(10 * time.Second)
	for !IsUserUnmitigated(fp) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if !IsUserUnmitigated(fp) {
		t.Error("release marker not visible to processThreat after 10s; the " +
			"next blocked request would re-apply the mitigation immediately")
	}
}

// A fingerprint block used to have no expiry: it sat in the table until removed
// by hand. For a key that identifies a client class rather than a client, a
// permanent block taken automatically on one moment's evidence is the wrong
// default — the attacker changes a header and comes back, the bystanders who
// share the class do not.
//
// Against the pre-fix query, which had no time bound, this fails: the
// mitigation is still in force long after its TTL.
func TestUserMitigationExpiresAfterTTL(t *testing.T) {
	freshStore(t)

	orig := mitigationTTL
	mitigationTTL = 1 * time.Second
	defer func() { mitigationTTL = orig }()

	const fp = "ttl-ja4plus|203.0.113"
	MarkUserMitigated(fp, "JA4+", "blocked", "waf")
	if !IsUserMitigated(fp) {
		t.Fatal("not mitigated immediately after being marked")
	}

	// CURRENT_TIMESTAMP is second-granular, so step well clear of the boundary.
	time.Sleep(2500 * time.Millisecond)

	if IsUserMitigated(fp) {
		t.Errorf("still blocked %v after a %v TTL; a coarse fingerprint block that "+
			"never expires keeps bystanders out with nobody aware of it",
			2500*time.Millisecond, mitigationTTL)
	}
}

// A release has to say whether it released anything, and it has to say it
// about mitigations rather than about its own bookkeeping: the DELETE inside
// MarkUserUnmitigated also removes the UNMITIGATED_MARKER row a previous
// release inserted under the same key, so rows-affected would call a second
// release a success.
func TestMarkUserUnmitigatedReportsWhatItReleased(t *testing.T) {
	freshStore(t)

	const fp = "release-report-ja4plus|203.0.113"

	if MarkUserUnmitigated(fp) {
		t.Error("reported a release for a fingerprint that was never mitigated")
	}

	MarkUserMitigated(fp, "JA4+", "blocked", "waf")
	if !MarkUserUnmitigated(fp) {
		t.Error("an in-force mitigation was released but not reported as one")
	}
	if MarkUserUnmitigated(fp) {
		t.Error("a repeat release reported success for deleting its own marker row")
	}
}

// The TTL must not resurrect an explicit release, and must not be so eager that
// a fresh block is useless.
func TestUserMitigationHoldsWithinTTL(t *testing.T) {
	freshStore(t)

	const fp = "ttl-hold-ja4plus|203.0.113"
	MarkUserMitigated(fp, "JA4+", "blocked", "waf")
	time.Sleep(1100 * time.Millisecond)

	if !IsUserMitigated(fp) {
		t.Errorf("block expired inside its %v TTL", mitigationTTL)
	}
}
