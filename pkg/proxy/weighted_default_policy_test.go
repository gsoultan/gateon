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

// namedBackends starts one backend per name; each answers with its name in
// X-Backend, so a test can see where the proxy sent every request.
func namedBackends(t *testing.T, names ...string) map[string]string {
	t.Helper()
	urls := make(map[string]string, len(names))
	for _, name := range names {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Backend", name)
		}))
		t.Cleanup(srv.Close)
		urls[name] = srv.URL
	}
	return urls
}

// proxyFor builds the handler production builds for a route on svc, from a
// real service registry.
func proxyFor(t *testing.T, svc *gateonv1.Service) *ProxyHandler {
	t.Helper()
	reg := config.NewServiceRegistry(filepath.Join(t.TempDir(), "services.json"))
	if err := reg.Update(context.Background(), svc); err != nil {
		t.Fatal(err)
	}
	ph := NewProxyHandler(&gateonv1.Route{Id: svc.Id + "-route", ServiceId: svc.Id}, reg)
	t.Cleanup(ph.Close)
	return ph
}

// sequence sends n requests through ph and returns the backend each reached.
func sequence(t *testing.T, ph http.Handler, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for range n {
		rec := httptest.NewRecorder()
		ph.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://gw.test/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		out = append(out, rec.Header().Get("X-Backend"))
	}
	return out
}

func longestRun(seq []string, name string) int {
	longest, run := 0, 0
	for _, s := range seq {
		if s == name {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return longest
}

// TestDefaultPolicyHonoursTargetWeights: the service form shows a Weight on
// every target -- "Higher weight = more traffic" -- under the default policy,
// round robin, which ignored it: weights 1:2:6 gave 30/30/30.
func TestDefaultPolicyHonoursTargetWeights(t *testing.T) {
	urls := namedBackends(t, "a", "b", "c")
	ph := proxyFor(t, &gateonv1.Service{
		Id: "weighted", Name: "weighted", // no policy: the default
		WeightedTargets: []*gateonv1.Target{
			{Url: urls["a"], Weight: 1}, {Url: urls["b"], Weight: 2}, {Url: urls["c"], Weight: 6},
		},
	})
	got := map[string]int{}
	for _, name := range sequence(t, ph, 90) {
		got[name]++
	}
	if got["a"] != 10 || got["b"] != 20 || got["c"] != 60 {
		t.Fatalf("90 requests over weights 1:2:6 under the default policy went %v, want a:10 b:20 c:60", got)
	}
}

// TestWeightedPicksAreInterleaved: weighted round robin sent each target its
// whole weight in one run -- at 6:1:1, six requests in a row to one backend --
// so a canary at 50/50 took whole bursts. A smooth schedule interleaves them.
func TestWeightedPicksAreInterleaved(t *testing.T) {
	urls := namedBackends(t, "heavy", "x", "y")
	targets := []*gateonv1.Target{
		{Url: urls["heavy"], Weight: 6}, {Url: urls["x"], Weight: 1}, {Url: urls["y"], Weight: 1},
	}
	for _, policy := range []string{"", "weighted_round_robin"} {
		ph := proxyFor(t, &gateonv1.Service{Id: "smooth" + policy, LoadBalancerPolicy: policy, WeightedTargets: targets})
		seq := sequence(t, ph, 80)
		if run := longestRun(seq, "heavy"); run > 4 {
			t.Errorf("policy %q: the weight-6 target took %d requests in a row, want at most 4 (smooth: two per gap, and two more across a cycle boundary): %v",
				policy, run, seq[:16])
		}
	}
}

// TestEqualWeightsStillRotate: a service whose targets all carry the same
// weight -- what the form saves by default -- is plain rotation.
func TestEqualWeightsStillRotate(t *testing.T) {
	urls := namedBackends(t, "a", "b", "c")
	ph := proxyFor(t, &gateonv1.Service{Id: "equal", WeightedTargets: []*gateonv1.Target{
		{Url: urls["a"], Weight: 1}, {Url: urls["b"], Weight: 1}, {Url: urls["c"], Weight: 1},
	}})
	seq := sequence(t, ph, 6)
	for i := 3; i < 6; i++ {
		if seq[i] != seq[i-3] || seq[i] == seq[i-1] {
			t.Fatalf("equal weights did not rotate: %v", seq)
		}
	}
}

// TestADownTargetsShareFollowsTheWeights: a turn that falls on a target the
// health check ejected goes to the live ones in proportion to their weights,
// not to whichever is next in the list.
func TestADownTargetsShareFollowsTheWeights(t *testing.T) {
	urls := namedBackends(t, "a", "b", "dead")
	ph := proxyFor(t, &gateonv1.Service{Id: "ejected", WeightedTargets: []*gateonv1.Target{
		{Url: urls["a"], Weight: 1}, {Url: urls["b"], Weight: 3}, {Url: urls["dead"], Weight: 4},
	}})
	ph.lb.SetAlive(urls["dead"], false)
	got := map[string]int{}
	for _, name := range sequence(t, ph, 80) {
		got[name]++
	}
	if got["dead"] != 0 || got["a"] != 20 || got["b"] != 60 {
		t.Fatalf("with the weight-4 target down, 80 requests went %v, want a:20 b:60", got)
	}
}

// TestWeightsBeyondTheScheduleBoundKeepTheirProportions: a cycle longer than
// maxScheduleLen is not interleaved, but its proportions still hold.
func TestWeightsBeyondTheScheduleBoundKeepTheirProportions(t *testing.T) {
	lb := NewDefaultLoadBalancerFactory().Create("round_robin", []*gateonv1.Target{
		{Url: "http://big", Weight: 4999}, {Url: "http://small", Weight: 1},
	})
	if rr, ok := lb.(*RoundRobinLB); !ok || rr.set.Load().order != nil {
		t.Fatal("a 5000-entry cycle was scheduled; the bound is maxScheduleLen")
	}
	got := map[string]int{}
	for range 10000 {
		got[lb.Next()]++
	}
	if got["http://big"] != 9998 || got["http://small"] != 2 {
		t.Fatalf("10000 picks over 4999:1 went %v, want big:9998 small:2", got)
	}
}
