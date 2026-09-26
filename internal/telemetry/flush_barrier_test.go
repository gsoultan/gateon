// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
)

// TestFlushThreatsIsABarrier is the regression test for a flush that returned
// before the threats queued ahead of it had been processed.
//
// FlushThreats promises that everything enqueued before the call has been
// processed and persisted when it returns, and RemoveMitigatedThreat relies on
// exactly that: it flushes first so that a threat still in the queue cannot
// re-penalise the client after the release. But the writer took its intake and
// the flush request from one select, and select picks at random among ready
// cases -- so the flush usually ran with most of the queue still waiting, and a
// release could be undone by threats that arrived before it.
//
// One call, no retry loop: the property is that a single FlushThreats is
// enough.
func TestFlushThreatsIsABarrier(t *testing.T) {
	freshStore(t)
	const ip = "203.0.113.9"
	t.Cleanup(func() { ResetReputation(ip) })

	const n = 200
	for range n {
		RecordSecurityThreat(SecurityThreat{
			Type:        "probe_detected",
			SourceIP:    ip,
			Score:       1,
			Severity:    "low",
			ActionTaken: ActionDetected,
		})
	}
	FlushThreats()

	if got := CountSecurityThreats(t.Context(), nil); got != n {
		t.Fatalf("FlushThreats returned with %d of %d queued threats persisted; "+
			"the rest were still in the queue behind it", got, n)
	}
}
