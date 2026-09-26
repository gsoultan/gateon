// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type stubTargetHealth TargetHealthCounts

func (s stubTargetHealth) TargetHealthCounts() TargetHealthCounts { return TargetHealthCounts(s) }

// TestRealtimeTilesCountTargetsAndCircuits: the realtime snapshot read the
// dashboard's target tiles from gateon_target_health by a "status" label the
// gauge does not have, and the gauge exists only for health-checked targets.
// Three targets with one down read as 0 healthy of 2, with no open circuit.
// It now takes target health from the load balancers, and counts a down target
// and an open route breaker as open circuits, as /v1/diag/agg-stats does.
func TestRealtimeTilesCountTargetsAndCircuits(t *testing.T) {
	SetTargetHealthProvider(stubTargetHealth{Healthy: 2, Down: 1, Total: 3})
	t.Cleanup(func() { SetTargetHealthProvider(nil) })
	// What the health-check loop publishes for the same three targets: the
	// old reader's input, so it cannot pass by reading nothing.
	TargetHealth.WithLabelValues("tiles-route", "http://a").Set(1)
	TargetHealth.WithLabelValues("tiles-route", "http://b").Set(1)
	TargetHealth.WithLabelValues("tiles-route", "http://c").Set(0)
	// A breaker publishes all three of its states, 1 for the one it is in.
	for route, state := range map[string]string{"tiles-open": "open", "tiles-half": "half-open", "tiles-closed": "closed"} {
		for _, s := range []string{"closed", "open", "half-open"} {
			v := 0.0
			if s == state {
				v = 1
			}
			CircuitBreakerState.WithLabelValues(route, s).Set(v)
		}
		t.Cleanup(func() { CircuitBreakerState.DeletePartialMatch(prometheus.Labels{"route": route}) })
	}
	t.Cleanup(func() { TargetHealth.DeletePartialMatch(prometheus.Labels{"route": "tiles-route"}) })

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	idx := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		idx[f.GetName()] = f
	}
	gs := buildGoldenSignals(t.Context(), idx)

	for _, c := range []struct {
		name      string
		got, want float64
	}{
		{"HealthyTargets", gs.HealthyTargets, 2},
		{"TotalTargets", gs.TotalTargets, 3},
		{"OpenCircuits", gs.OpenCircuits, 2},
		{"HalfOpenCircuits", gs.HalfOpenCircuits, 1},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}
