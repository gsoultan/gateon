// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gsoultan/gateon/internal/telemetry"
	"github.com/gsoultan/gateon/pkg/proxy"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func breakerSeries(t *testing.T, route string) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() { telemetry.CircuitBreakerState.Collect(ch); close(ch) }()
	n := 0
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("read gauge: %v", err)
		}
		for _, l := range d.GetLabel() {
			if l.GetName() == "route" && l.GetValue() == route {
				n++
			}
		}
	}
	return n
}

// TestSyncForgetsTheBreakerOfADeletedRoute: circuit breaker state is keyed by
// route label in a process-wide map, and nothing removed an entry. A route
// deleted while its circuit was open went on counting as an open circuit on
// the dashboard until the process restarted. Sync is where the cache already
// notices deleted routes.
func TestSyncForgetsTheBreakerOfADeletedRoute(t *testing.T) {
	f, _ := newCacheFixture(t, "none")
	if err := f.mws.Update(t.Context(), &gateonv1.Middleware{
		Id: "cb", Name: "cb", Type: "circuit_breaker", Config: map[string]string{"min_requests": "1"},
	}); err != nil {
		t.Fatalf("middleware: %v", err)
	}
	const route = "breaker-route-sync"
	keep := f.route(t, "breaker-route-kept", "cb")
	rt := f.route(t, route, "cb")
	for _, r := range []*gateonv1.Route{keep, rt} {
		if rec := serveThrough(f.cache.GetOrCreate(r)); rec.Code != http.StatusOK {
			t.Fatalf("route %s answered %d, want 200", r.Id, rec.Code)
		}
	}
	if n := breakerSeries(t, route); n != 3 {
		t.Fatalf("breaker gauge series for the route = %d, want 3 (closed, open, half-open)", n)
	}

	if err := f.routes.Delete(t.Context(), route); err != nil {
		t.Fatalf("delete route: %v", err)
	}
	f.cache.Sync()

	if n := breakerSeries(t, route); n != 0 {
		t.Errorf("breaker gauge series of a deleted route after Sync = %d, want 0", n)
	}
	if n := breakerSeries(t, keep.Id); n != 3 {
		t.Errorf("breaker gauge series of a route that still exists = %d, want 3", n)
	}
}

// TestProxyCacheCountsTargetsWithoutAHealthCheck: the realtime tiles counted
// targets from gateon_target_health, which only a health check publishes, so
// a route without one had no targets on the dashboard at all.
func TestProxyCacheCountsTargetsWithoutAHealthCheck(t *testing.T) {
	f, _ := newCacheFixture(t, "none")
	rt := f.route(t, "counted-route")
	if rec := serveThrough(f.cache.GetOrCreate(rt)); rec.Code != http.StatusOK {
		t.Fatalf("route answered %d, want 200", rec.Code)
	}
	got := f.cache.TargetHealthCounts()
	if want := (telemetry.TargetHealthCounts{Healthy: 1, Total: 1}); got != want {
		t.Fatalf("TargetHealthCounts = %+v, want %+v", got, want)
	}
}

// TestServerGivesTheSnapshotItsTargets: the realtime tiles read target health
// from whatever provider Run registered, so the registration is the fix as
// much as the provider is.
func TestServerGivesTheSnapshotItsTargets(t *testing.T) {
	f, _ := newCacheFixture(t, "none")
	rt := f.route(t, "registered-route")
	s := &Server{cache: f.cache}
	s.cacheOnce.Do(func() {})
	registerTelemetryProviders(s)
	t.Cleanup(func() { telemetry.SetTargetHealthProvider(nil) })

	serveThrough(f.cache.GetOrCreate(rt))
	if got := telemetry.CurrentTargetHealth(); got.Total != 1 || got.Healthy != 1 {
		t.Fatalf("snapshot's target health after Run's registration = %+v, want 1 healthy of 1", got)
	}
}

// TestRebuiltRouteKeepsItsDownTargets: invalidation deletes a route's handler
// and the next request builds a fresh one, whose targets all started alive --
// every configuration save sent traffic back to backends known to be down,
// until the new handler's first check fifteen seconds later.
func TestRebuiltRouteKeepsItsDownTargets(t *testing.T) {
	f, _ := newCacheFixture(t, "none")
	svc, ok := f.cache.serviceStore.Get(t.Context(), "svc")
	if !ok {
		t.Fatal("fixture service missing")
	}
	svc.HealthCheckPath = "/health"
	if err := f.cache.serviceStore.Update(t.Context(), svc); err != nil {
		t.Fatal(err)
	}
	rt := f.route(t, "health-route")
	f.cache.GetOrCreate(rt)
	target := svc.WeightedTargets[0].Url
	// Stand in for the health loop concluding the target is down.
	f.cache.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)[rt.Id].
		InheritHealth(map[string]bool{target: false})

	f.cache.InvalidateRoute(rt.Id)
	f.cache.GetOrCreate(rt)
	stats := f.cache.GetRouteStats(rt.Id)
	if len(stats) != 1 || stats[0].Alive {
		t.Fatalf("after a rebuild the route's target = %+v, want it still down", stats)
	}
}

// TestPurgedRouteKeepsItsDownTargets is the same for Purge, which the
// resource governor calls under memory pressure: it dropped every handler
// without keeping what their health checks had concluded, so after a purge
// every route sent traffic to backends known to be down until each new
// handler's first check -- under pressure, the worst moment for it.
func TestPurgedRouteKeepsItsDownTargets(t *testing.T) {
	f, _ := newCacheFixture(t, "none")
	svc, ok := f.cache.serviceStore.Get(t.Context(), "svc")
	if !ok {
		t.Fatal("fixture service missing")
	}
	svc.HealthCheckPath = "/health"
	if err := f.cache.serviceStore.Update(t.Context(), svc); err != nil {
		t.Fatal(err)
	}
	rt := f.route(t, "purged-health-route")
	f.cache.GetOrCreate(rt)
	target := svc.WeightedTargets[0].Url
	f.cache.proxyHandlers.Load().(map[string]*proxy.ProxyHandler)[rt.Id].
		InheritHealth(map[string]bool{target: false})

	f.cache.Purge()
	f.cache.GetOrCreate(rt)
	stats := f.cache.GetRouteStats(rt.Id)
	if len(stats) != 1 || stats[0].Alive {
		t.Fatalf("after a purge the route's target = %+v, want it still down", stats)
	}
}

// Breakers are kept under their route's ID and report under its name. Sync
// retains them by ID; handing it the names instead would forget every live
// route whose name is not its ID -- its breaker reset, its gauge gone -- every
// thirty seconds.
func TestSyncKeepsTheBreakerOfANamedRoute(t *testing.T) {
	f, _ := newCacheFixture(t, "none")
	if err := f.mws.Update(t.Context(), &gateonv1.Middleware{
		Id: "cb", Name: "cb", Type: "circuit_breaker", Config: map[string]string{"min_requests": "1"},
	}); err != nil {
		t.Fatalf("middleware: %v", err)
	}
	rt := &gateonv1.Route{Id: "breaker-named-id", Name: "Breaker Named", ServiceId: "svc",
		Rule: "PathPrefix(`/`)", Middlewares: []string{"cb"}}
	if err := f.routes.Update(t.Context(), rt); err != nil {
		t.Fatalf("route: %v", err)
	}
	if rec := serveThrough(f.cache.GetOrCreate(rt)); rec.Code != http.StatusOK {
		t.Fatalf("route answered %d, want 200", rec.Code)
	}
	f.cache.Sync()
	if n := breakerSeries(t, rt.Name); n != 3 {
		t.Fatalf("breaker gauge series of a live route named %q after Sync = %d, want 3", rt.Name, n)
	}
}
