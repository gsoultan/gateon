// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/internal/telemetry/repid"
)

// Through the middlewares every route carries: an address block and a
// fingerprint block written before a restart are refused after it, with the
// database hung, and no lookup is made for either (ADR 0058). Before the
// block list both were served -- the cache knew nothing after the restart,
// and a lookup that cannot finish decides its request served (ADR 0043).
func TestBlocksWrittenBeforeARestartAreRefusedWithTheDatabaseHung(t *testing.T) {
	t.Setenv("GATEON_BLOCK_LOOKUP_TIMEOUT", lookupDeadline.String())
	t.Setenv("GATEON_TRACE_DIR", filepath.Join(t.TempDir(), "traces"))
	path := filepath.Join(t.TempDir(), "telemetry.db")
	open := func() {
		_ = telemetry.ClosePathStatsStore(t.Context())
		if err := telemetry.InitPathStatsStore(path, 1); err != nil {
			t.Fatalf("init telemetry store: %v", err)
		}
	}
	open()
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })
	const blockedIP, client = "198.51.100.231", "198.51.100.232"
	if err := telemetry.MarkIPMitigated(blockedIP, "before the restart"); err != nil {
		t.Fatal(err)
	}
	key := repid.For(chromeJA4Plus, client)
	telemetry.MarkUserMitigated(key, "JA4+", "before the restart", "waf")

	open() // the restart
	h := hangLookupDB(t)
	if code := answeredWithin(t, "IPMitigation", func() int { return ipMitigationStatus(blockedIP) }); code != http.StatusForbidden {
		t.Errorf("an address blocked before the restart got %d, want 403", code)
	}
	code := answeredWithin(t, "UserMitigation", func() int {
		c, _ := userMitigationStatus(chromeJA4Plus, client)
		return c
	})
	if code != http.StatusForbidden {
		t.Errorf("a fingerprint blocked before the restart got %d, want 403", code)
	}
	if n := h.Queries(); n != 0 {
		t.Errorf("%d block-list queries, want none", n)
	}
}
