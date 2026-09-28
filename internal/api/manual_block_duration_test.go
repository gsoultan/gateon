// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"path/filepath"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// The mitigate API gains an optional duration for a manual IP block (ADR
// 0037): a positive duration_seconds sets the block's expires_at so it lapses
// on its own, and zero leaves it open-ended as before. The duration must reach
// the stored row, not be dropped between the request and the write.

// TestMitigateThreatRoundTripsAManualDuration: MitigateThreat with a positive
// duration_seconds blocks the address and records the expiry the request asked
// for; the mitigation list reports it.
func TestMitigateThreatRoundTripsAManualDuration(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "mitigate.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })

	const ip = "203.0.113.90"
	svc := &ApiService{}
	res, err := svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{
		Source:          ip,
		Type:            "IP",
		DurationSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("MitigateThreat: %v", err)
	}
	if !res.Success {
		t.Fatalf("a valid bounded block was refused: %s", res.Message)
	}
	if !telemetry.IsIPMitigated(ip) {
		t.Fatalf("%s is not blocked after a bounded MitigateThreat", ip)
	}

	list, total := telemetry.GetIPMitigations(t.Context(), 50, 0)
	if total != 1 || len(list) != 1 {
		t.Fatalf("the mitigation list holds %d rows, want 1", total)
	}
	end := list[0].ExpiresAt
	if end == nil {
		t.Fatal("the block the API set with duration_seconds=3600 has no expiry; the duration was dropped")
	}
	if got := end.Sub(list[0].MitigatedAt); got < 3590*1e9 || got > 3610*1e9 {
		t.Errorf("the stored expiry is %v after the block, not the ~1h the request asked for", got)
	}
}

// TestMitigateThreatWithoutADurationIsOpenEnded: the default is unchanged -- a
// manual block with no duration keeps no expiry and holds until released.
func TestMitigateThreatWithoutADurationIsOpenEnded(t *testing.T) {
	if err := telemetry.InitPathStatsStore(filepath.Join(t.TempDir(), "mitigate.db"), 1); err != nil {
		t.Fatalf("init telemetry store: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.ClosePathStatsStore(t.Context()) })

	const ip = "203.0.113.91"
	svc := &ApiService{}
	if _, err := svc.MitigateThreat(t.Context(), &gateonv1.MitigateThreatRequest{Source: ip, Type: "IP"}); err != nil {
		t.Fatalf("MitigateThreat: %v", err)
	}
	list, total := telemetry.GetIPMitigations(t.Context(), 50, 0)
	if total != 1 || len(list) != 1 {
		t.Fatalf("the mitigation list holds %d rows, want 1", total)
	}
	if list[0].ExpiresAt != nil {
		t.Errorf("an open-ended manual block carries an expiry (%v); it would lapse on its own",
			list[0].ExpiresAt)
	}
}
