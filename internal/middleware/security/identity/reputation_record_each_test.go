// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/request"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestEveryReputationBlockIsStored: the blocker gave its threat the ID
// "rep-block-<route>-<identity>", the same for every refusal of one client on
// one route, so the store's primary key refused every row after the first.
// Twenty refusals were one row on the Threats and Blocks pages, and every
// total, trend and top-N read from the table undercounted by the same amount,
// while Mitigated Today and the funnel -- counted before the insert -- showed
// all twenty.
func TestEveryReputationBlockIsStored(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "rep-each.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	defer telemetry.ClosePathStatsStore(context.Background())

	const blocks = 3
	probe := withState(httptest.NewRequest(http.MethodGet, "/", nil), &request.RequestState{})
	probe.RemoteAddr = "198.51.100.91:4321"
	id := telemetry.GetReputationID(probe)
	telemetry.DecreaseReputation(id, 100, "test")
	defer telemetry.ResetReputation(id)

	blocker := ReputationBlocker("rep-each-route")(okOrigin())
	for range blocks {
		req := withState(httptest.NewRequest(http.MethodGet, "/", nil), &request.RequestState{})
		req.RemoteAddr = probe.RemoteAddr
		rr := httptest.NewRecorder()
		blocker.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("client at reputation 0: got %d, want 403", rr.Code)
		}
	}
	telemetry.FlushThreats()

	got := telemetry.CountSecurityThreats(t.Context(), &telemetry.ThreatFilter{Search: "198.51.100.91"})
	if got != blocks {
		t.Fatalf("stored %d reputation blocks, want %d: one row per refusal", got, blocks)
	}
}
