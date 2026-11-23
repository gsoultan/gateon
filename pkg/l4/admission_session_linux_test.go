// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package l4

import "testing"

// TestReachesBackendEndsItsSessionBeforeReturning: the helper the SSH route
// tests share must not leave its proxied session running after it returns.
// Root cause of the intermittent TestSplicedSessionsCountsTheSessionsBeingSpliced
// failure ("2 spliced sessions ... want 1"): reachesBackend started ProxyTCP on
// a goroutine and returned once the echo came back, so the session was still
// counted by the process-wide gauge while whichever test ran next -- in a
// shuffled order, the gauge's own test -- read it.
func TestReachesBackendEndsItsSessionBeforeReturning(t *testing.T) {
	for range 50 {
		backend := newCountingEcho(t)
		r, _, ep := filteredSSH(t, backend.addr)
		if !reachesBackend(t, r, ep) {
			t.Fatal("the unfiltered route did not reach the backend")
		}
		if n := SplicedSessions(); n != 0 {
			t.Fatalf("%d sessions still spliced after reachesBackend returned, want 0", n)
		}
	}
}
