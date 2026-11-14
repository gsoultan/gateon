// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"
	"time"
)

// TestMitigatedTodayRestoresTheUTCDayInTheWritersZone: Mitigated Today counts
// from UTC midnight -- the rollover resets it then -- but a restart restored it
// by comparing UTC midnight, as text, against timestamps written in the
// gateway's local wall clock. East of UTC that took in the previous day's
// evening: at 00:30 in Jakarta the figure counted from 00:00 Jakarta time, seven
// hours before the day it was meant to count began.
func TestMitigatedTodayRestoresTheUTCDayInTheWritersZone(t *testing.T) {
	freshStore(t)
	st := getStore()
	jakarta := time.FixedZone("WIB", 7*60*60)

	// 00:30 on the 14th in Jakarta is 17:30 on the 13th UTC: the UTC day began
	// at 07:00 on the 13th, Jakarta time.
	now := time.Date(2026, 11, 14, 0, 30, 0, 0, jakarta)
	for _, at := range []time.Time{
		time.Date(2026, 11, 13, 8, 0, 0, 0, jakarta), // 01:00 UTC on the 13th: today
		time.Date(2026, 11, 13, 6, 0, 0, 0, jakarta), // 23:00 UTC on the 12th: yesterday
	} {
		RecordSecurityThreat(SecurityThreat{
			SourceIP: "203.0.113.40", Type: "waf_blocked", Category: "waf",
			Severity: "high", ActionTaken: ActionBlocked, Time: at,
		})
	}
	FlushThreats()

	st.seedDailyCounters(now, jakarta)
	if got := GetMitigatedRolling24h(t.Context()); got != 1 {
		t.Fatalf("Mitigated Today restored as %d, want 1: only the threat since 00:00 UTC", got)
	}
}
