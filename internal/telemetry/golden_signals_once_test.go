// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

func gaugeOf(value float64, labels map[string]string) *dto.Metric {
	m := &dto.Metric{Gauge: &dto.Gauge{Value: proto.Float64(value)}}
	for k, v := range labels {
		m.Label = append(m.Label, &dto.LabelPair{Name: proto.String(k), Value: proto.String(v)})
	}
	return m
}

// TestTheHeadlineCountsEveryRequestFamilySeriesOnce: since ADR 0061 a request
// is in the per-route families once -- under its route, or under
// "gateon-<entrypoint>" when no route took it. The headline read only the
// "gateon-" series, which used to hold every request; read that way now it
// would show only the unrouted ones. Ten routed requests (two of them 5xx)
// and two unrouted are twelve, with two errors; in flight is the entrypoint
// gauge's, which encloses the route's.
func TestTheHeadlineCountsEveryRequestFamilySeriesOnce(t *testing.T) {
	idx := map[string]*dto.MetricFamily{
		"gateon_requests_total": famOf(
			counterMetric(8, map[string]string{"route": "shop", "status_code": "200"}),
			counterMetric(2, map[string]string{"route": "shop", "status_code": "502"}),
			counterMetric(2, map[string]string{"route": "gateon-web", "status_code": "404"}),
		),
		"gateon_requests_in_flight": famOf(
			gaugeOf(3, map[string]string{"route": "shop"}),
		),
		"gateon_entrypoint_requests_in_flight": famOf(
			gaugeOf(4, map[string]string{"entrypoint": "web"}),
		),
	}
	gs := onceScopedSignals(idx)
	if gs.RequestsTotal != 12 || gs.ErrorsTotal != 2 {
		t.Errorf("requests %v, errors %v; want 12 and 2", gs.RequestsTotal, gs.ErrorsTotal)
	}
	if gs.InFlightTotal != 4 {
		t.Errorf("in flight %v, want the entrypoint gauge's 4", gs.InFlightTotal)
	}
	delete(idx, "gateon_entrypoint_requests_in_flight")
	if gs := onceScopedSignals(idx); gs.InFlightTotal != 3 {
		t.Errorf("in flight %v with no entrypoint gauge, want the routes' 3", gs.InFlightTotal)
	}
}
