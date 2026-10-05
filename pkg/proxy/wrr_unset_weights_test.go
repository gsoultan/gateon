// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gsoultan/gateon/internal/config"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestWeightedServiceWithNoWeightsServes proxies through a weighted
// round-robin service whose targets carry no weight -- proto3's zero, which is
// what a service saved without touching the weights holds, including the
// repository's own dev and e2e configs. The balancer summed the weights to
// zero and answered 502 "no targets available" to every request.
func TestWeightedServiceWithNoWeightsServes(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("a")) }))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("b")) }))
	defer b.Close()

	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{
		Id: "unweighted", Name: "unweighted", LoadBalancerPolicy: "weighted_round_robin",
		WeightedTargets: []*gateonv1.Target{{Url: a.URL}, {Url: b.URL}},
	}); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "unweighted-route", ServiceId: "unweighted"}, reg)
	defer ph.Close()

	seen := map[string]int{}
	for range 10 {
		rec := httptest.NewRecorder()
		ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d body %q; a service with unset weights must still serve", rec.Code, rec.Body)
		}
		seen[rec.Body.String()]++
	}
	if seen["a"] == 0 || seen["b"] == 0 {
		t.Fatalf("unset weights should spread traffic evenly, got %v", seen)
	}
}

// TestAStandbyServesWhenEveryWeightedTargetIsDown is TRUTH-NEW-12. A target at
// weight 0 beside weighted ones is "on standby" (ADR 0047), but it never took
// a request even with every weighted target down: the route answered 503 with
// a live standby in its pool. Standbys now share the traffic, evenly, while no
// weighted target is alive, and go back to nothing when one returns.
func TestAStandbyServesWhenEveryWeightedTargetIsDown(t *testing.T) {
	const primary, s1, s2 = "http://primary.internal", "http://standby-1.internal", "http://standby-2.internal"
	lb := NewWeightedRoundRobinLB([]*gateonv1.Target{
		{Url: s1, Weight: 0}, {Url: primary, Weight: 3}, {Url: s2, Weight: 0},
	})
	lb.SetAlive(primary, false)
	seen := map[string]int{}
	for range 20 {
		seen[lb.Next()]++
	}
	if seen[s1] != 10 || seen[s2] != 10 {
		t.Fatalf("with the only weighted target down, 20 picks went %v; want the two live standbys 10 each", seen)
	}

	lb.SetAlive(s1, false)
	for range 4 {
		if got := lb.Next(); got != s2 {
			t.Fatalf("with one standby left, a pick went to %q", got)
		}
	}

	lb.SetAlive(primary, true)
	for range 10 {
		if got := lb.Next(); got != primary {
			t.Fatalf("the weighted target is back but a pick went to %q", got)
		}
	}

	lb.SetAlive(primary, false)
	lb.SetAlive(s2, false)
	if got := lb.Next(); got != "" {
		t.Fatalf("every target down, standbys included, but a pick went to %q", got)
	}
}

// TestARouteFailsOverToItsStandby: the same through the proxy, with the
// primary ejected by its health check rather than by hand.
func TestARouteFailsOverToItsStandby(t *testing.T) {
	primary := newSwitchableBackend(t, "primary")
	standby := namedBackends(t, "standby")["standby"]
	ph := proxyFor(t, &gateonv1.Service{Id: "failover", WeightedTargets: []*gateonv1.Target{
		{Url: primary.url(), Weight: 1}, {Url: standby, Weight: 0},
	}})
	if got := sequence(t, ph, 4); got[0] != "primary" || got[3] != "primary" {
		t.Fatalf("with the primary up, requests went to %v", got)
	}
	primary.stop()
	ph.checkAll(t.Context(), ph.healthHTTPClient())
	ph.checkAll(t.Context(), ph.healthHTTPClient())

	rec := httptest.NewRecorder()
	ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gw.test/", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("X-Backend") != "standby" {
		t.Fatalf("primary down, standby up: status %d from %q, want 200 from the standby",
			rec.Code, rec.Header().Get("X-Backend"))
	}
}

// TestZeroWeightStaysStandbyBesideAWeightedTarget keeps the fix from turning a
// canary held at 0% into a live one: weight zero next to a weighted target
// still receives nothing.
func TestZeroWeightStaysStandbyBesideAWeightedTarget(t *testing.T) {
	// The canary first: the balancer walks targets in order, so a zero-weight
	// target listed after a weighted one is never reached whatever its rule.
	lb := NewWeightedRoundRobinLB([]*gateonv1.Target{
		{Url: "http://canary.internal", Weight: 0},
		{Url: "http://stable.internal", Weight: 1},
	})
	for range 20 {
		if got := lb.Next(); got != "http://stable.internal" {
			t.Fatalf("a zero-weight canary received a request: %q", got)
		}
	}
}
