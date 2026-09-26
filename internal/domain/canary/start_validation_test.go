// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package canary

import (
	"errors"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func weightedService(policy string) *gateonv1.Service {
	return &gateonv1.Service{
		Id: "shop", LoadBalancerPolicy: policy,
		WeightedTargets: []*gateonv1.Target{{Url: "http://stable", Weight: 100}, {Url: "http://canary", Weight: 0}},
	}
}

func shiftTo(weights ...int32) *gateonv1.StartCanaryRequest {
	req := &gateonv1.StartCanaryRequest{ServiceId: "shop", Steps: 1, DurationMinutes: 1}
	for i, url := range []string{"http://stable", "http://canary"} {
		req.TargetWeights = append(req.TargetWeights, &gateonv1.Target{Url: url, Weight: weights[i]})
	}
	return req
}

// TestCanaryRefusesAServiceThatIgnoresWeights: a canary shifts traffic by
// shifting target weights, and only weighted round robin reads them. On any
// other policy the rollout logged its progress while every request went where
// it always had -- and StartCanary answered success for it.
func TestCanaryRefusesAServiceThatIgnoresWeights(t *testing.T) {
	for _, policy := range []string{"", "round_robin", "least_conn", "roundRobin"} {
		cs, fake := canaryService(weightedService(policy))
		_, err := cs.StartCanary(t.Context(), shiftTo(50, 50))
		if !errors.Is(err, ErrNotRunnable) || !strings.Contains(err.Error(), "weighted round robin") {
			t.Errorf("policy %q: err = %v, want ErrNotRunnable naming weighted round robin", policy, err)
		}
		if n := fake.saveCount(); n != 0 {
			t.Errorf("policy %q: a refused canary saved the service %d times", policy, n)
		}
	}
	for _, policy := range []string{"weighted_round_robin", "weightedRoundRobin"} {
		cs, _ := canaryService(weightedService(policy))
		if _, err := cs.StartCanary(t.Context(), shiftTo(50, 50)); err != nil {
			t.Errorf("policy %q refused: %v", policy, err)
		}
	}
}

// TestCanaryRefusesWhatItCannotFind: a missing service, or target weights
// naming none of its targets, used to start a rollout that ended at once in
// the log -- after the API had already reported it started.
func TestCanaryRefusesWhatItCannotFind(t *testing.T) {
	cs, _ := canaryService(nil)
	if _, err := cs.StartCanary(t.Context(), shiftTo(50, 50)); !errors.Is(err, ErrNotRunnable) {
		t.Errorf("missing service: err = %v, want ErrNotRunnable", err)
	}
	cs, _ = canaryService(weightedService("weighted_round_robin"))
	req := &gateonv1.StartCanaryRequest{ServiceId: "shop", TargetWeights: []*gateonv1.Target{{Url: "http://elsewhere", Weight: 1}}}
	if _, err := cs.StartCanary(t.Context(), req); !errors.Is(err, ErrNotRunnable) {
		t.Errorf("weights for no target of the service: err = %v, want ErrNotRunnable", err)
	}
}
