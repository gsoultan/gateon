// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestTarpitThresholdIsAThreatScore pins the direction of the tarpit's
// threshold, which shares its label -- "when IP threat score exceeds this" --
// with proof-of-work's. Proof-of-work read that label backwards and challenged
// nobody (T10, ADR 0045); the tarpit read it right, and this keeps it so: a
// client whose threat score (100 - reputation) is above the threshold is
// delayed, one below it is not.
//
// The delay is the observable. A delayed request cannot finish before its
// sleep, so the slow case cannot pass by accident; the fast cases allow the
// whole delay as slack for a loaded runner.
func TestTarpitThresholdIsAThreatScore(t *testing.T) {
	const delay = 300 * time.Millisecond
	cases := []struct {
		name      string
		peer      string
		penalty   float64
		threshold float64
		delayed   bool
	}{
		{"threat 50 exceeds 7", "100.64.81.1", 50, 7, true},
		{"threat 50 does not reach 60", "100.64.82.1", 50, 60, false},
		{"a clean client has threat 0", "100.64.83.1", 0, 7, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer + ":4444"
			id := telemetry.GetReputationID(req)
			if tc.penalty > 0 {
				telemetry.DecreaseReputation(id, tc.penalty, "test: tarpit threshold")
			}
			t.Cleanup(func() { telemetry.ResetReputation(id) })
			if got := 100 - telemetry.GetReputationScore(id); got != tc.penalty {
				t.Fatalf("threat score %v, want %v; the rest of this test would prove nothing", got, tc.penalty)
			}

			h := Tarpit(delay, delay, tc.threshold)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			start := time.Now()
			h.ServeHTTP(httptest.NewRecorder(), req)
			if got := time.Since(start) >= delay; got != tc.delayed {
				t.Errorf("threat %v at threshold %v: delayed=%v, want %v", tc.penalty, tc.threshold, got, tc.delayed)
			}
		})
	}
}
