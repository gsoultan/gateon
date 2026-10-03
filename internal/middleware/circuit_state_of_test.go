// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package middleware

import (
	"net/http"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
)

// TestCircuitStateOfReportsTheBreaker: the dashboard's target rows read a
// route's breaker through CircuitStateOf (ADR 0047), so it must follow the
// breaker through every state, and say when there is none.
func TestCircuitStateOfReportsTheBreaker(t *testing.T) {
	if _, ok := CircuitStateOf(t.Name()); ok {
		t.Fatal("a breaker is reported for a key that has none")
	}
	rig := newBreakerRig(t, quickBreaker())
	want := func(s telemetry.CircuitState) {
		t.Helper()
		if got, ok := CircuitStateOf(t.Name()); !ok || got != s {
			t.Fatalf("CircuitStateOf = %q (found %v), want %q", got, ok, s)
		}
	}
	want(telemetry.CircuitClosed)
	rig.open()
	want(telemetry.CircuitOpen)
	rig.clock.Advance(31 * time.Second)
	probe := rig.park(http.StatusOK, "X-Hold")
	want(telemetry.CircuitHalfOpen)
	rig.finish(probe)
	want(telemetry.CircuitClosed)
}
