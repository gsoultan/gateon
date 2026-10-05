// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entrypoint

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/middleware"
	"github.com/gsoultan/gateon/internal/router"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// onceChains are a routed and an unrouted handler behind the real chain of
// one entrypoint, "once-ep", whose route is "r-once".
func onceChains(t *testing.T, inBackend func()) (routed, unrouted http.Handler) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inBackend()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	dir := t.TempDir()
	services := config.NewServiceRegistry(filepath.Join(dir, "services.json"))
	mws := config.NewMiddlewareRegistry(filepath.Join(dir, "middlewares.json"))
	global := config.NewGlobalRegistry(filepath.Join(dir, "global.json"))
	if err := services.Update(t.Context(), &gateonv1.Service{
		Id: "svc-once", WeightedTargets: []*gateonv1.Target{{Url: upstream.URL, Weight: 1}},
	}); err != nil {
		t.Fatalf("service: %v", err)
	}
	ep := &gateonv1.EntryPoint{Id: "once-ep", Name: "once-ep", Address: ":8080"}
	deps := &Deps{GlobalStore: global}
	rt := &gateonv1.Route{Id: "r-once", Name: "r-once", ServiceId: "svc-once", Rule: "PathPrefix(`/`)", Type: "http"}
	ph := proxy.NewProxyHandler(rt, services)
	t.Cleanup(ph.Close)
	routed = middleware.Chain(entrypointChain(t.Context(), ep, deps)...)(
		router.ApplyRouteMiddlewares(ph, rt, nil, mws, global, nil, nil))
	unrouted = middleware.Chain(entrypointChain(t.Context(), ep, deps)...)(http.NotFoundHandler())
	return routed, unrouted
}

// requestSeries sums family over the series whose route is one of routes:
// counters by value, histograms by sample count.
func requestSeries(t *testing.T, family string, routes ...string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	want := map[string]bool{}
	for _, r := range routes {
		want[r] = true
	}
	var total float64
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			if want[seriesLabel(m, "route")] || want[seriesLabel(m, "entrypoint")] {
				total += m.GetCounter().GetValue() + float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return total
}

func seriesLabel(m *dto.Metric, name string) string {
	for _, l := range m.GetLabel() {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// TestEachRequestIsInTheRequestFamiliesOnce is OPS-N8: the entrypoint's
// metrics recorded every request under "gateon-<entrypoint>" and the route's
// recorded the same request under the route, so any sum over
// gateon_requests_total or the duration histogram -- the runbook's 5xx-rate
// and latency alerts, the WAF rollout's would-block fraction -- counted every
// proxied request twice. Four routed requests and one unrouted are five in
// both families, and five in the entrypoint's own view.
func TestEachRequestIsInTheRequestFamiliesOnce(t *testing.T) {
	routed, unrouted := onceChains(t, func() {})
	routes := []string{"r-once", "gateon-once-ep"}
	families := []string{"gateon_requests_total", "gateon_request_duration_seconds"}
	before := map[string]float64{}
	for _, f := range families {
		before[f] = requestSeries(t, f, routes...)
	}
	epBefore := requestSeries(t, "gateon_entrypoint_requests_total", "once-ep")

	for range 4 {
		serveFunnel(t, routed, "/page", "198.51.100.23:5000", http.StatusOK)
	}
	serveFunnel(t, unrouted, "/nowhere", "198.51.100.23:5000", http.StatusNotFound)

	for _, f := range families {
		if got := requestSeries(t, f, routes...) - before[f]; got != 5 {
			t.Errorf("%s moved by %v for 5 requests (4 routed, 1 unrouted)", f, got)
		}
	}
	if got := requestSeries(t, "gateon_entrypoint_requests_total", "once-ep") - epBefore; got != 5 {
		t.Errorf("gateon_entrypoint_requests_total moved by %v for 5 requests on the entrypoint", got)
	}
}

// gaugeSeries sums a gauge family over the series whose route or entrypoint
// label is one of names.
func gaugeSeries(t *testing.T, family string, names ...string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Errorf("gather: %v", err)
		return -1
	}
	var total float64
	for _, f := range families {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, n := range names {
				if seriesLabel(m, "route") == n || seriesLabel(m, "entrypoint") == n {
					total += m.GetGauge().GetValue()
				}
			}
		}
	}
	return total
}

// TestARequestInFlightIsInTheRouteGaugeOnce: while the backend serves a routed
// request, gateon_requests_in_flight holds it once -- under its route -- and
// the entrypoint's own gauge holds it too. It used to be under the route and
// under "gateon-<entrypoint>", two in flight for one request.
func TestARequestInFlightIsInTheRouteGaugeOnce(t *testing.T) {
	var routeGauge, epGauge float64
	routed, _ := onceChains(t, func() {
		routeGauge = gaugeSeries(t, "gateon_requests_in_flight", "r-once", "gateon-once-ep")
		epGauge = gaugeSeries(t, "gateon_entrypoint_requests_in_flight", "once-ep")
	})
	serveFunnel(t, routed, "/page", "198.51.100.23:5000", http.StatusOK)
	if routeGauge != 1 || epGauge != 1 {
		t.Errorf("one request in the backend: gateon_requests_in_flight %v, entrypoint gauge %v; want 1 and 1",
			routeGauge, epGauge)
	}
}
