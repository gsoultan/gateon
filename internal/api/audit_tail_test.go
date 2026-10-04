// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/audit"
)

// TestVerifyResponseIsNotIntactWithItsTailMissing (ADR 0057): a log cut from
// the end has no break in what is left, so intact must come from the tail
// check as well, or every transport answers "intact" over it.
func TestVerifyResponseIsNotIntactWithItsTailMissing(t *testing.T) {
	at := time.Date(2026, 10, 4, 9, 30, 0, 0, time.UTC)
	cut := verifyResponse(audit.VerifyResult{Checked: 7, Complete: true, TailMissing: true, TailAnchor: at})
	if cut.GetIntact() || !cut.GetTailMissing() || cut.GetTailAnchorTimestamp() != at.Format(time.RFC3339Nano) {
		t.Errorf("a cut log answered intact=%v tail_missing=%v anchor=%q; want not intact, the anchor's time",
			cut.GetIntact(), cut.GetTailMissing(), cut.GetTailAnchorTimestamp())
	}
	whole := verifyResponse(audit.VerifyResult{Checked: 7, Complete: true, TailAnchor: at})
	if !whole.GetIntact() || whole.GetTailMissing() || whole.GetTailAnchorTimestamp() == "" {
		t.Errorf("an intact log answered %v; want intact with the tail it checked", whole)
	}
	unchecked := verifyResponse(audit.VerifyResult{Checked: 7, Complete: true})
	if unchecked.GetTailAnchorTimestamp() != "" {
		t.Errorf("no tail was checked, yet the answer names one: %q", unchecked.GetTailAnchorTimestamp())
	}
}
