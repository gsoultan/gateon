// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"fmt"
	"testing"
	"time"
)

// resetAddressEvidence clears the escalation's per-address table.
func resetAddressEvidence() {
	addressEvidenceMu.Lock()
	defer addressEvidenceMu.Unlock()
	addressEvidence.Purge()
}

// addressClassCount is how many classes the table holds against ip.
func addressClassCount(ip string) int {
	addressEvidenceMu.Lock()
	defer addressEvidenceMu.Unlock()
	v, ok := addressEvidence.Get(ip)
	if !ok {
		return 0
	}
	s, ok := v.(*addressSightings)
	if !ok || s == nil {
		return 0
	}
	return s.n
}

// The table's own rules, with the clock in the test's hands.

// A class counts for a window after its latest evidence, not its first: one
// that keeps attacking stays counted.
func TestAClassThatKeepsAttackingStaysCounted(t *testing.T) {
	resetAddressEvidence()
	t.Cleanup(resetAddressEvidence)
	const ip = "198.51.100.30"
	t0 := time.Now()

	recordAddressEvidence(ip, "class-a", t0)
	recordAddressEvidence(ip, "class-a", t0.Add(9*time.Minute))
	if got := recordAddressEvidence(ip, "class-b", t0.Add(15*time.Minute)); got != 2 {
		t.Errorf("a class that attacked 6 minutes ago was not counted beside a new one: %d classes, want 2", got)
	}
	if got := recordAddressEvidence(ip, "class-c", t0.Add(26*time.Minute)); got != 1 {
		t.Errorf("classes silent for over %s still counted: %d classes, want 1", mitigationEvidenceWindow, got)
	}
}

// A threat the store reaches after newer evidence, older than the window
// before it, is not counted: it would add up with evidence it never overlapped.
func TestALatePieceOfEvidenceIsNotCounted(t *testing.T) {
	resetAddressEvidence()
	t.Cleanup(resetAddressEvidence)
	const ip = "198.51.100.31"
	t0 := time.Now()
	for i := range ipShunMinClasses - 1 {
		recordAddressEvidence(ip, fmt.Sprintf("recent-%d", i), t0)
	}
	if got := recordAddressEvidence(ip, "stale", t0.Add(-mitigationEvidenceWindow-time.Second)); got != ipShunMinClasses-1 {
		t.Errorf("evidence from before the window was counted: %d classes, want %d", got, ipShunMinClasses-1)
	}
}

// An address keeps at most ipShunMinClasses classes, and a full entry stays at
// the bar as new classes arrive.
func TestAnAddressHoldsAtMostTheBar(t *testing.T) {
	resetAddressEvidence()
	t.Cleanup(resetAddressEvidence)
	const ip = "198.51.100.32"
	t0 := time.Now()
	for i := range ipShunMinClasses + 3 {
		got := recordAddressEvidence(ip, fmt.Sprintf("class-%d", i), t0.Add(time.Duration(i)*time.Second))
		if want := min(i+1, ipShunMinClasses); got != want {
			t.Fatalf("after %d classes: %d counted, want %d", i+1, got, want)
		}
	}
}

// The table is keyed by the source address, which an attacker chooses.
func TestTheEvidenceTableIsBounded(t *testing.T) {
	resetAddressEvidence()
	t.Cleanup(resetAddressEvidence)
	now := time.Now()
	for i := range maxEvidenceAddresses + 500 {
		recordAddressEvidence(fmt.Sprintf("2001:db8::%x", i), "class", now)
	}
	addressEvidenceMu.Lock()
	n := addressEvidence.Len()
	addressEvidenceMu.Unlock()
	if n > maxEvidenceAddresses {
		t.Errorf("the table holds %d addresses; its bound is %d", n, maxEvidenceAddresses)
	}
}

// A release forgets the evidence against the address, whether or not it had
// reached a shun.
func TestAReleaseForgetsTheEvidence(t *testing.T) {
	freshStore(t)
	resetAddressEvidence()
	t.Cleanup(resetAddressEvidence)
	const ip = "198.51.100.33"
	for i := range ipShunMinClasses - 1 {
		recordAddressEvidence(ip, fmt.Sprintf("class-%d", i), time.Now())
	}
	if err := MarkIPUnmitigated(ip); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := addressClassCount(ip); got != 0 {
		t.Errorf("after a release the table still holds %d classes against %s", got, ip)
	}
}

// A threat stamped in the future -- a clock that disagrees with this one --
// cannot push the window forward and make current evidence look old.
func TestEvidenceIsNeverDatedLaterThanNow(t *testing.T) {
	future := &SecurityThreat{Time: time.Now().Add(time.Hour)}
	if got := evidenceTime(future); got.After(time.Now()) {
		t.Errorf("a threat stamped an hour ahead was dated %s, after now", got)
	}
	past := time.Now().Add(-time.Minute)
	if got := evidenceTime(&SecurityThreat{Time: past}); !got.Equal(past) {
		t.Errorf("a threat stamped a minute ago was dated %s, want %s", got, past)
	}
}
