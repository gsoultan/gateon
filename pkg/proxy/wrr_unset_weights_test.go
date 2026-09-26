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
