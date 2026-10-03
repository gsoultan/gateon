// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package service

import (
	"errors"
	"strings"
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func targets(weights ...int32) []*gateonv1.Target {
	out := make([]*gateonv1.Target, len(weights))
	for i, w := range weights {
		out[i] = &gateonv1.Target{Url: "http://t" + string(rune('a'+i)), Weight: w}
	}
	return out
}

// TestSaveRefusesASettingTheGatewayWouldNotCarryOut: each of these saved with
// 200 and then did something other than what it said (ADR 0043, ADR 0047).
func TestSaveRefusesASettingTheGatewayWouldNotCarryOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		svc  *gateonv1.Service
		says string
	}{
		{"an unknown policy, balanced round robin",
			&gateonv1.Service{LoadBalancerPolicy: "ip_hash", WeightedTargets: targets(1)}, `"ip_hash"`},
		{"weights under least connections, which ignores them",
			&gateonv1.Service{LoadBalancerPolicy: "leastConn", WeightedTargets: targets(1, 5)}, "least_conn ignores target weights"},
		{"weights under the predictive balancer",
			&gateonv1.Service{LoadBalancerPolicy: "ai_predictive", WeightedTargets: targets(0, 1)}, "ai_predictive ignores"},
		{"weights on a TCP service",
			&gateonv1.Service{BackendType: "tcp", WeightedTargets: targets(1, 2)}, "tcp service ignores target weights"},
		{"a negative weight",
			&gateonv1.Service{WeightedTargets: targets(1, -1)}, "weight -1"},
		{"an HTTP health check with nothing to request, which checked nothing",
			&gateonv1.Service{HealthCheckType: gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, WeightedTargets: targets(1)},
			"HTTP health check needs a path"},
		{"a negative threshold",
			&gateonv1.Service{UnhealthyThreshold: -1, WeightedTargets: targets(1)}, "thresholds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeServiceStore{services: map[string]*gateonv1.Service{}}
			s := NewService(store, &fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
			err := s.SaveService(t.Context(), tc.svc)
			if !errors.Is(err, ErrInvalidService) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want ErrInvalidService saying %q", err, tc.says)
			}
			if len(store.services) != 0 {
				t.Fatal("a refused service was stored")
			}
		})
	}
}

// TestSaveKeepsWhatTheGatewayCarriesOut: weights under round robin (the
// default) and weighted round robin, equal weights under any policy, and the
// dashboard's default health check (Auto, no path) all save.
func TestSaveKeepsWhatTheGatewayCarriesOut(t *testing.T) {
	for _, svc := range []*gateonv1.Service{
		{WeightedTargets: targets(1, 2, 6)},
		{LoadBalancerPolicy: "roundRobin", WeightedTargets: targets(0, 100)},
		{LoadBalancerPolicy: "weightedRoundRobin", WeightedTargets: targets(1, 2)},
		{LoadBalancerPolicy: "least_conn", WeightedTargets: targets(1, 1)},
		{BackendType: "udp", LoadBalancerPolicy: "leastConn", WeightedTargets: targets(0, 0)},
		{HealthCheckType: gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_HTTP, HealthCheckPath: "/hz", WeightedTargets: targets(1)},
		{HealthCheckType: gateonv1.HealthCheckType_HEALTH_CHECK_TYPE_TCP, WeightedTargets: targets(1)},
	} {
		s := NewService(&fakeServiceStore{services: map[string]*gateonv1.Service{}},
			&fakeRouteStore{updateErr: map[string]error{}}, &recordingInvalidator{}, nil)
		if err := s.SaveService(t.Context(), svc); err != nil {
			t.Errorf("%v refused: %v", svc, err)
		}
	}
}
