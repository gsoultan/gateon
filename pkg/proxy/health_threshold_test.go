// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package proxy

import (
	"testing"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// The health checker had no failure or recovery threshold: every check result
// was passed straight to the load balancer, so one failed check removed a
// backend and one successful check brought it back.
//
// That is worse than it sounds. Every target is checked in one loop on one
// goroutine, so whatever makes a single check fail -- a GC pause, a scheduling
// delay, a moment of load on the gateway itself -- tends to fail all of them in
// the same tick. The balancer returns nothing when no target is alive, so a
// service goes fully dark because the gateway was busy for a moment, with every
// backend healthy the whole time.

// feed replays a sequence of results and returns every state change reported.
func feed(h *healthThresholds, target string, results []bool) []bool {
	var changes []bool
	for _, ok := range results {
		if alive, changed := h.record(target, ok); changed {
			changes = append(changes, alive)
		}
	}
	return changes
}

// TestHealthThresholdIgnoresASingleBlip is the regression.
func TestHealthThresholdIgnoresASingleBlip(t *testing.T) {
	h := newHealthThresholds(2, 2)

	// Establish the target as alive, then fail exactly one check.
	changes := feed(h, "http://b1", []bool{true, false, true, true})

	if len(changes) != 1 || changes[0] != true {
		t.Errorf("state changes = %v, want a single change to alive.\n"+
			"One failed check between successes took the backend out of rotation. "+
			"Because every target is checked in the same loop, the blip that "+
			"caused it usually hits all of them at once, and an empty pool serves "+
			"nothing.", changes)
	}
}

// TestHealthThresholdRemovesAPersistentlyFailingTarget is the other half.
//
// Tolerating a blip must not mean tolerating a dead backend.
func TestHealthThresholdRemovesAPersistentlyFailingTarget(t *testing.T) {
	h := newHealthThresholds(2, 2)

	changes := feed(h, "http://b1", []bool{true, false, false})
	if len(changes) != 2 || changes[1] != false {
		t.Errorf("state changes = %v, want alive then dead; two consecutive "+
			"failures is the configured threshold and must act", changes)
	}

	// Further failures are not repeated to the balancer.
	if more := feed(h, "http://b1", []bool{false, false, false}); len(more) != 0 {
		t.Errorf("a target already marked dead reported %v more changes; the "+
			"balancer is told about transitions, not results", more)
	}
}

// TestHealthThresholdRequiresSustainedRecovery covers the flap-back.
func TestHealthThresholdRequiresSustainedRecovery(t *testing.T) {
	h := newHealthThresholds(2, 2)
	feed(h, "http://b1", []bool{true, false, false}) // now dead

	if changes := feed(h, "http://b1", []bool{true}); len(changes) != 0 {
		t.Errorf("one successful check returned the target to rotation (%v); a "+
			"backend failing intermittently would rejoin on its first lucky "+
			"response and immediately take traffic", changes)
	}
	if changes := feed(h, "http://b1", []bool{true}); len(changes) != 1 || !changes[0] {
		t.Errorf("the second consecutive success gave %v, want a change to alive", changes)
	}
}

// TestHealthThresholdResetsAnInterruptedStreak pins that the count is
// consecutive rather than cumulative.
//
// Failures scattered across hours are a different thing from failures in a row,
// and only the second means the backend is gone.
func TestHealthThresholdResetsAnInterruptedStreak(t *testing.T) {
	h := newHealthThresholds(3, 2)

	if changes := feed(h, "http://b1", []bool{
		true,
		false, true,
		false, true,
		false, true,
	}); len(changes) != 1 {
		t.Errorf("state changes = %v, want only the initial one. Six failures "+
			"separated by successes are not three in a row, and counting them "+
			"cumulatively would eventually remove every backend that ever had a "+
			"bad moment.", changes)
	}
}

// TestHealthThresholdAppliesTheFirstResultImmediately covers startup.
//
// A gateway that has just started knows nothing about its backends. Making a
// newly discovered target wait two intervals before it can be used -- or two
// intervals before an already-dead one stops being used -- treats an absence of
// history as evidence.
func TestHealthThresholdAppliesTheFirstResultImmediately(t *testing.T) {
	h := newHealthThresholds(2, 2)

	if alive, changed := h.record("http://fresh", true); !changed || !alive {
		t.Error("a first successful check did not put a new target into rotation; " +
			"it would sit idle for a threshold's worth of intervals after startup")
	}
	if alive, changed := h.record("http://broken", false); !changed || alive {
		t.Error("a first failed check did not keep a new target out of rotation; " +
			"a backend that is already down would receive traffic until the " +
			"threshold cleared")
	}
}

// TestHealthThresholdTracksTargetsSeparately guards the obvious mix-up.
func TestHealthThresholdTracksTargetsSeparately(t *testing.T) {
	h := newHealthThresholds(2, 2)
	h.record("http://b1", true)
	h.record("http://b2", true)

	// b1 fails twice; b2 is fine throughout.
	h.record("http://b1", false)
	h.record("http://b2", true)
	if alive, _ := h.record("http://b1", false); alive {
		t.Error("b1 should be dead after two consecutive failures")
	}
	if alive, changed := h.record("http://b2", false); !alive || changed {
		t.Error("b2 changed state on its first failure; b1's failures are not b2's")
	}
}

// TestHealthThresholdDefaultsAreApplied covers the zero value.
//
// An unset proto field is 0, which must mean "use the default" rather than "a
// threshold of zero" -- the latter would either act on nothing or act on
// everything, depending on how the comparison happened to be written.
func TestHealthThresholdDefaultsAreApplied(t *testing.T) {
	h := newHealthThresholds(0, 0)
	if h.unhealthy != defaultUnhealthyThreshold || h.healthy != defaultHealthyThreshold {
		t.Fatalf("thresholds = (%d, %d), want the defaults (%d, %d)",
			h.unhealthy, h.healthy, defaultUnhealthyThreshold, defaultHealthyThreshold)
	}
	// And it behaves, rather than merely holding the right numbers.
	if changes := feed(h, "http://b1", []bool{true, false}); len(changes) != 1 {
		t.Errorf("with defaults, a single failure produced %v; want no change", changes)
	}

	// A negative value is nonsense and must not disable the check.
	if n := newHealthThresholds(-1, -5); n.unhealthy <= 0 || n.healthy <= 0 {
		t.Errorf("negative thresholds survived as (%d, %d)", n.unhealthy, n.healthy)
	}
}

// TestHealthThresholdCanBeConfiguredBackToImmediate covers the operator who
// wants the old behaviour.
//
// Detection speed is a real trade and the default now costs one extra interval.
// An operator who would rather have it back must be able to say so.
func TestHealthThresholdCanBeConfiguredBackToImmediate(t *testing.T) {
	h := newHealthThresholds(1, 1)
	changes := feed(h, "http://b1", []bool{true, false, true})
	if len(changes) != 3 {
		t.Errorf("with thresholds of 1, changes = %v; want every result to act, "+
			"which is what the setting is for", changes)
	}
}

// TestHealthThresholdForgetsRetiredTargets covers the bound.
//
// The history is a map keyed by backend URL in a process that outlives any
// individual backend, so discovery churn would grow it without limit.
func TestHealthThresholdForgetsRetiredTargets(t *testing.T) {
	h := newHealthThresholds(2, 2)
	for _, u := range []string{"http://b1", "http://b2", "http://b3"} {
		h.record(u, true)
	}
	h.forget("http://b2")

	h.mu.Lock()
	_, still := h.state["http://b2"]
	n := len(h.state)
	h.mu.Unlock()

	if still || n != 2 {
		t.Errorf("after forgetting b2 the history holds %d entries (b2 present: %v), "+
			"want 2; a map keyed by backend needs an eviction path or it grows for "+
			"the life of the process", n, still)
	}

	// A returning target starts fresh, which is the same position a restart
	// leaves the gateway in.
	if alive, changed := h.record("http://b2", false); !changed || alive {
		t.Error("a target that came back did not have its first result applied " +
			"immediately")
	}
}

// TestHealthThresholdIsSafeUnderConcurrentChecks covers the lock.
func TestHealthThresholdIsSafeUnderConcurrentChecks(t *testing.T) {
	h := newHealthThresholds(2, 2)
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				h.record("http://b1", j%2 == 0)
				h.record("http://b2", true)
				if j%50 == 0 {
					h.forget("http://b3")
				}
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// TestServiceThresholdsReachTheHealthChecker proves the setting is wired.
//
// A configuration key that nothing reads is this project's most-repeated defect:
// 73 middleware settings were inert because the dashboard wrote one spelling and
// Go read another, and every one of them looked configured. Reading the code and
// concluding "the whole message is persisted, so it flows through" is exactly
// the reasoning that missed it the first time.
//
// So this asserts the value arrives, rather than that the plumbing looks right.
func TestServiceThresholdsReachTheHealthChecker(t *testing.T) {
	rt := &gateonv1.Route{Id: "test", ServiceId: "test"}

	t.Run("configured values are used", func(t *testing.T) {
		svc := &gateonv1.Service{
			Id:                 "test",
			WeightedTargets:    []*gateonv1.Target{{Url: "http://backend:8080"}},
			UnhealthyThreshold: 5,
			HealthyThreshold:   3,
		}
		ph := NewProxyHandlerBuilder(rt, &mockServiceStore{svc: svc}, nil).Build()
		defer ph.Close()

		if ph.healthThresholds == nil {
			t.Fatal("the handler has no threshold tracker; every check result would " +
				"go straight to the balancer")
		}
		if ph.healthThresholds.unhealthy != 5 || ph.healthThresholds.healthy != 3 {
			t.Errorf("thresholds = (%d, %d), want (5, 3) from the service config. "+
				"The values are set on the Service message and never reach the "+
				"checker, so the setting reads as configured and does nothing.",
				ph.healthThresholds.unhealthy, ph.healthThresholds.healthy)
		}
	})

	t.Run("an unset service gets the defaults", func(t *testing.T) {
		svc := &gateonv1.Service{
			Id:              "test",
			WeightedTargets: []*gateonv1.Target{{Url: "http://backend:8080"}},
		}
		ph := NewProxyHandlerBuilder(rt, &mockServiceStore{svc: svc}, nil).Build()
		defer ph.Close()

		if ph.healthThresholds.unhealthy != defaultUnhealthyThreshold ||
			ph.healthThresholds.healthy != defaultHealthyThreshold {
			t.Errorf("thresholds = (%d, %d), want the defaults (%d, %d)",
				ph.healthThresholds.unhealthy, ph.healthThresholds.healthy,
				defaultUnhealthyThreshold, defaultHealthyThreshold)
		}
	})
}
