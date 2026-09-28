// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// An automatic shun lapses (ADR 0031), and the IP mitigation list says when,
// as it does for a kernel throttle: the row carries the shun's end, which the
// dashboard counts down to ("lifts in 42m"). An operator's block has no end,
// and its row carries none.
func TestAnAutomaticShunIsListedWithWhenItLifts(t *testing.T) {
	s, _ := throttleTestService(t)
	res, err := telemetry.ShunAutomatically("10.64.1.1", "Anomaly detection: test")
	if err != nil || res.Outcome != telemetry.ShunApplied {
		t.Fatalf("automatic shun: %+v, %v", res, err)
	}
	if err := telemetry.MarkIPMitigated("10.64.1.2", "Manually mitigated by administrator"); err != nil {
		t.Fatal(err)
	}

	resp, err := s.ListSecurityThreats(t.Context(), &gateonv1.ListSecurityThreatsRequest{Status: "ipMitigated", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]*gateonv1.Anomaly{}
	for _, a := range resp.GetThreats() {
		rows[a.GetSource()] = a
	}
	auto, manual := rows["10.64.1.1"], rows["10.64.1.2"]
	if auto == nil || manual == nil {
		t.Fatalf("both shuns should be listed: %v", rows)
	}
	if want := res.Until.UTC().Format(time.RFC3339); auto.GetExpiresAt() != want {
		t.Errorf("the automatic shun is listed lifting at %q, want %q", auto.GetExpiresAt(), want)
	}
	if manual.GetExpiresAt() != "" {
		t.Errorf("an operator's block, which holds until released, is listed lifting at %q", manual.GetExpiresAt())
	}
}
