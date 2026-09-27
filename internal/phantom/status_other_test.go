// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

//go:build !linux

package phantom

import "testing"

// TestStatusReportsTheStandardEngine: off Linux nothing splices, so the card
// must not claim zero-copy.
func TestStatusReportsTheStandardEngine(t *testing.T) {
	enabled, engine, sessions := NewPhantomCore().GetStatus()
	if enabled || engine != "standard" || sessions != 0 {
		t.Fatalf("GetStatus = (%v, %q, %d), want (false, \"standard\", 0): nothing splices here",
			enabled, engine, sessions)
	}
}
