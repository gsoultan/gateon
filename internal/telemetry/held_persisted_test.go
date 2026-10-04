// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"
)

// TestAStoredThreatSaysWhetherItIsHeldAgainstItsSource: Observed and
// Unattributed were not persisted, so every threat read back from the store
// was held against its source -- and the analysis engine, which reads stored
// threats, counted detections the gateway let through and leaks found in
// responses against the address (ADR 0059, migration 68).
func TestAStoredThreatSaysWhetherItIsHeldAgainstItsSource(t *testing.T) {
	freshStore(t)
	threats := []SecurityThreat{
		{ID: "held-observed", Type: "xss_detected", SourceIP: "100.64.50.10", ActionTaken: ActionDetected, Observed: true},
		{ID: "held-unattributed", Type: "data_exposure", SourceIP: "", ActionTaken: ActionRedacted, Unattributed: true},
		{ID: "held-refusal", Type: "waf_blocked", SourceIP: "100.64.50.11", ActionTaken: ActionBlocked},
	}
	for _, th := range threats {
		th.Time = time.Now()
		RecordSecurityThreat(th)
	}
	FlushThreats()

	listed := map[string]*SecurityThreat{}
	for _, th := range GetSecurityThreatsLite(t.Context(), 100, 0, nil) {
		listed[th.ID] = th
	}
	for _, want := range threats {
		got, ok := listed[want.ID]
		if !ok {
			t.Fatalf("%s was not listed", want.ID)
		}
		one, err := GetSecurityThreatByID(t.Context(), want.ID)
		if err != nil {
			t.Fatalf("%s: %v", want.ID, err)
		}
		for name, read := range map[string]*SecurityThreat{"the list": got, "the detail": one} {
			if read.Observed != want.Observed || read.Unattributed != want.Unattributed ||
				read.HeldAgainstSource() != want.HeldAgainstSource() {
				t.Errorf("%s read back from %s as observed=%v unattributed=%v held=%v, recorded as %v/%v/%v",
					want.ID, name, read.Observed, read.Unattributed, read.HeldAgainstSource(),
					want.Observed, want.Unattributed, want.HeldAgainstSource())
			}
		}
	}
}

// TestRefusedWhenRecorded is what the request path did, not what holds now.
func TestRefusedWhenRecorded(t *testing.T) {
	for action, want := range map[string]bool{
		ActionBlocked: true, ActionChallenged: true, ActionShunned: true,
		ActionDetected: false, ActionFlagged: false, ActionThrottled: false, ActionRedacted: false, "": false,
	} {
		th := SecurityThreat{ActionTaken: action, Mitigated: true}
		if got := th.RefusedWhenRecorded(); got != want {
			t.Errorf("action %q: RefusedWhenRecorded = %v, want %v", action, got, want)
		}
	}
}
