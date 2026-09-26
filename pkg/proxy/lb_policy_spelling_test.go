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

// TestDashboardSpelledWeightedPolicyHonoursWeights balances a service saved the
// way the dashboard saves it, with the policy spelled "weightedRoundRobin".
// The factory matched only "weighted_round_robin", so the service fell through
// to plain round robin: weights 3:1 split traffic 50/50 while the service page
// showed weighted round robin -- and a canary rollout, which works by moving
// weights, moved nothing.
func TestDashboardSpelledWeightedPolicyHonoursWeights(t *testing.T) {
	heavy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("heavy")) }))
	defer heavy.Close()
	light := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("light")) }))
	defer light.Close()

	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), &gateonv1.Service{
		Id: "dash-weighted", Name: "dash-weighted", LoadBalancerPolicy: "weightedRoundRobin",
		WeightedTargets: []*gateonv1.Target{{Url: heavy.URL, Weight: 3}, {Url: light.URL, Weight: 1}},
	}); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: "dash-weighted-route", ServiceId: "dash-weighted"}, reg)
	defer ph.Close()

	counts := map[string]int{}
	for range 100 {
		rec := httptest.NewRecorder()
		ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		counts[rec.Body.String()]++
	}
	if counts["heavy"] < 65 {
		t.Fatalf("weights 3:1 under policy %q split traffic %v; want about 75/25", "weightedRoundRobin", counts)
	}
}

// TestCanonicalLBPolicyAcceptsEverySpelling pins the mapping itself, since both
// the HTTP and the L4 balancer switch on its output.
func TestCanonicalLBPolicyAcceptsEverySpelling(t *testing.T) {
	for in, want := range map[string]string{
		"": "round_robin", "roundRobin": "round_robin", "round_robin": "round_robin",
		"leastConn": "least_conn", "least_conn": "least_conn", "LEAST-CONN": "least_conn",
		"weightedRoundRobin": "weighted_round_robin", "weighted_round_robin": "weighted_round_robin",
		"ai_predictive": "ai_predictive", "intelligent": "intelligent",
	} {
		if got := config.CanonicalLBPolicy(in); got != want {
			t.Errorf("CanonicalLBPolicy(%q) = %q, want %q", in, got, want)
		}
	}
}
