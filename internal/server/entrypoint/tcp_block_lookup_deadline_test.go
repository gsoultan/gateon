// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/middleware/security/identity"
	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/testutil"
)

// With Postgres frozen, a TCP entrypoint's connections waited for the block
// list before a byte was read -- from a new address, from one seen a minute
// before, and from loopback, whose exemption was read only after the lookup --
// for as long as Postgres stayed frozen (2026-10-04 review, DP-N1). A
// connection is now decided within the lookup deadline, and loopback without
// the database (ADR 0054).
func TestATCPConnectionIsServedWithinTheLookupDeadlineWhenTheDatabaseHangs(t *testing.T) {
	const deadline = 50 * time.Millisecond
	const fresh, known = "198.51.100.91", "198.51.100.92"
	t.Setenv("GATEON_BLOCK_LOOKUP_TIMEOUT", deadline.String())
	withTelemetryStore(t)
	if identity.AddressBlocked(known) { // read once, while the database answers
		t.Fatalf("setup: %s is blocked", known)
	}
	backend, sessions := countingEcho(t)
	ep, deps := tcpEntrypoint(t, "blocklist-hung-db"), mockDepsForInspection(t)
	deps.L4Resolver = routesResolver(t, ep.Id, backend, false)
	tcpEntrypointFrom(t, ep, deps, nil, fresh, known, "127.0.0.1")

	// Registered after the entrypoint, so it runs before the entrypoint's
	// shutdown, which would otherwise wait on a connection still looking up.
	h := testutil.NewHangDB(t)
	restore := telemetry.SetBlockLookupDBForTest(h.DB)
	t.Cleanup(func() {
		h.Release()
		telemetry.WaitBlockLookupsForTest()
		restore()
	})

	for _, from := range []string{"a new address", "a known address", "loopback"} {
		start := time.Now()
		c := dialBounded(t, ep.Address)
		_ = c.SetDeadline(time.Now().Add(deadline + 950*time.Millisecond))
		_ = echoed(t, c, "from "+from+"\n")
		_ = c.Close()
		if took := time.Since(start); took > deadline+950*time.Millisecond {
			t.Errorf("a connection from %s took %v to be served against a %v lookup deadline", from, took, deadline)
		}
	}
	if n := sessions.Load(); n != 3 {
		t.Errorf("the backend was given %d sessions, want 3", n)
	}
	if n := h.Queries(); n != 1 {
		t.Errorf("%d block-list queries; only the new address's should reach the database", n)
	}
}
