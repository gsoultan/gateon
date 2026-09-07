// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// TestServiceThresholdsReachTheHealthChecker proves the setting is wired.
//
// A configuration key that nothing reads is this project's most-repeated defect:
// 73 middleware settings were inert because the dashboard wrote one spelling and
// Go read another, and every one of them looked configured. Reading the code and
// concluding "the whole message is persisted, so it flows through" is exactly
// the reasoning that missed it the first time.
//
// So this drives the tracker the handler was actually built with, rather than
// reading back the number that was put in. A value that arrives and is then
// ignored would pass the second check and fail this one.
func TestServiceThresholdsReachTheHealthChecker(t *testing.T) {
	rt := &gateonv1.Route{Id: "test", ServiceId: "test"}

	build := func(t *testing.T, svc *gateonv1.Service) *ProxyHandler {
		t.Helper()
		ph := NewProxyHandlerBuilder(rt, &mockServiceStore{svc: svc}, nil).Build()
		t.Cleanup(ph.Close)
		if ph.healthThresholds == nil {
			t.Fatal("the handler has no threshold tracker; every check result would " +
				"go straight to the balancer")
		}
		return ph
	}

	// failuresToRemove counts how many consecutive failures the handler needs
	// before it would tell the balancer a target is down.
	failuresToRemove := func(ph *ProxyHandler) int {
		ph.healthThresholds.Record("http://b", true) // establish alive
		for i := 1; i <= 10; i++ {
			if alive, changed := ph.healthThresholds.Record("http://b", false); changed && !alive {
				return i
			}
		}
		return -1
	}

	t.Run("configured value is used", func(t *testing.T) {
		ph := build(t, &gateonv1.Service{
			Id:                 "test",
			WeightedTargets:    []*gateonv1.Target{{Url: "http://backend:8080"}},
			UnhealthyThreshold: 5,
			HealthyThreshold:   3,
		})
		if got := failuresToRemove(ph); got != 5 {
			t.Errorf("the handler removed a target after %d consecutive failures, want "+
				"5 as configured on the Service. The value is set on the message and "+
				"never reaches the checker, so the setting reads as configured and "+
				"changes nothing.", got)
		}
	})

	t.Run("an unset service gets the default", func(t *testing.T) {
		ph := build(t, &gateonv1.Service{
			Id:              "test",
			WeightedTargets: []*gateonv1.Target{{Url: "http://backend:8080"}},
		})
		if got := failuresToRemove(ph); got != 2 {
			t.Errorf("with no threshold configured the handler removed a target after "+
				"%d failures, want the default of 2", got)
		}
	})
}
