// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

// buildRouteMetrics had no coverage. Its five per-family loops each repeated the
// same guard — skip Gateon's own "gateon-" management routes — and that guard is
// the whole reason the dashboard shows customer traffic rather than the gateway
// talking to itself. Centralising it into forEachRouteMetric is only safe if the
// behaviour is pinned, so it is pinned here.

func counterMetric(value float64, labels map[string]string) *dto.Metric {
	m := &dto.Metric{Counter: &dto.Counter{Value: proto.Float64(value)}}
	for k, v := range labels {
		m.Label = append(m.Label, &dto.LabelPair{Name: proto.String(k), Value: proto.String(v)})
	}
	return m
}

func famOf(metrics ...*dto.Metric) *dto.MetricFamily {
	return &dto.MetricFamily{Metric: metrics}
}

func routeByName(t *testing.T, got []RouteMetric, name string) *RouteMetric {
	t.Helper()
	for i := range got {
		if got[i].Route == name {
			return &got[i]
		}
	}
	return nil
}

func TestBuildRouteMetricsSkipsInternalRoutes(t *testing.T) {
	idx := map[string]*dto.MetricFamily{
		"gateon_requests_total": famOf(
			counterMetric(10, map[string]string{"route": "customer-api", "service": "svc", "status_code": "200"}),
			counterMetric(99, map[string]string{"route": "gateon-management", "service": "mgmt", "status_code": "200"}),
			counterMetric(5, map[string]string{"route": "", "status_code": "200"}),
		),
	}

	got := buildRouteMetrics(idx)

	if routeByName(t, got, "customer-api") == nil {
		t.Fatalf("customer route missing from %v", got)
	}
	if rm := routeByName(t, got, "gateon-management"); rm != nil {
		t.Errorf("internal route leaked into route metrics: %+v", rm)
	}
	if rm := routeByName(t, got, ""); rm != nil {
		t.Errorf("unlabelled metric produced a route entry: %+v", rm)
	}
}

func TestBuildRouteMetricsAggregates(t *testing.T) {
	idx := map[string]*dto.MetricFamily{
		"gateon_requests_total": famOf(
			counterMetric(80, map[string]string{"route": "api", "service": "svc", "status_code": "200"}),
			counterMetric(20, map[string]string{"route": "api", "status_code": "503"}),
		),
		"gateon_request_bytes_total": famOf(
			counterMetric(1000, map[string]string{"route": "api", "direction": "in"}),
			counterMetric(2000, map[string]string{"route": "api", "direction": "out"}),
			counterMetric(7, map[string]string{"route": "api", "direction": "sideways"}),
		),
		"gateon_request_failures_total": famOf(
			counterMetric(3, map[string]string{"route": "api", "reason": "timeout"}),
			counterMetric(0, map[string]string{"route": "api", "reason": "refused"}),
		),
	}

	got := buildRouteMetrics(idx)
	rm := routeByName(t, got, "api")
	if rm == nil {
		t.Fatal("route api missing")
	}

	if rm.Requests != 100 {
		t.Errorf("Requests = %v, want 100", rm.Requests)
	}
	// Only 5xx counts as an error; 200 must not.
	if rm.Errors != 20 {
		t.Errorf("Errors = %v, want 20 (5xx only)", rm.Errors)
	}
	if rm.ErrorRate != 20 {
		t.Errorf("ErrorRate = %v, want 20", rm.ErrorRate)
	}
	if rm.Service != "svc" {
		t.Errorf("Service = %q, want svc carried from the labelled sample", rm.Service)
	}
	if rm.StatusCodes["200"] != 80 || rm.StatusCodes["503"] != 20 {
		t.Errorf("StatusCodes = %v, want 200:80 503:20", rm.StatusCodes)
	}
	if rm.BytesIn != 1000 || rm.BytesOut != 2000 {
		t.Errorf("bytes in/out = %v/%v, want 1000/2000", rm.BytesIn, rm.BytesOut)
	}
	// A direction the switch does not know must be dropped, not added to either.
	if rm.BytesIn+rm.BytesOut != 3000 {
		t.Errorf("unknown direction leaked into byte totals: in=%v out=%v", rm.BytesIn, rm.BytesOut)
	}
	// A zero-valued failure reason is not worth a row.
	if len(rm.Failures) != 1 || rm.Failures[0].Label != "timeout" {
		t.Errorf("Failures = %+v, want only the non-zero timeout reason", rm.Failures)
	}
}

// A family that is not present must not panic or invent routes.
func TestBuildRouteMetricsToleratesMissingFamilies(t *testing.T) {
	got := buildRouteMetrics(map[string]*dto.MetricFamily{})
	if len(got) != 0 {
		t.Errorf("empty index produced %d routes, want 0", len(got))
	}
}
