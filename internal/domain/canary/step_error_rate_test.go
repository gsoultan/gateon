// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package canary

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// stepRuns numbers the runs of TestARollbackJudgesTheStepNotTheLifetime.
var stepRuns atomic.Int32

// TestARollbackJudgesTheStepNotTheLifetime: a canary step that failed half its
// requests was judged against the service's lifetime error rate, and 10 000
// healthy requests before it diluted 50 failures in 100 to 0.5% -- under a 5%
// limit, so the rollout carried on. The step is now judged on its own traffic,
// and the rollback is recorded where the dashboard shows it.
func TestARollbackJudgesTheStepNotTheLifetime(t *testing.T) {
	// The event timeline is process-wide: a fresh service id per run keeps a
	// second run (-count=2) from passing on the first run's event.
	id := fmt.Sprintf("shop-%d", stepRuns.Add(1))
	cs, fake := canaryService(&gateonv1.Service{Id: id, LoadBalancerPolicy: "round_robin",
		WeightedTargets: []*gateonv1.Target{{Url: "http://stable", Weight: 100}, {Url: "http://canary", Weight: 0}}})
	var reads atomic.Int32
	cs.readSignals = func(context.Context, string) telemetry.GoldenSignals {
		if reads.Add(1) == 1 { // the rollout's start: a long healthy history
			return telemetry.GoldenSignals{RequestsTotal: 10000, ErrorsTotal: 0, ErrorRate: 0}
		}
		// After the first step: 100 more requests, 50 of them failed.
		return telemetry.GoldenSignals{RequestsTotal: 10100, ErrorsTotal: 50, ErrorRate: 50.0 / 10100 * 100}
	}
	req := shiftTo(0, 100)
	req.ServiceId = id
	req.Steps, req.DurationMinutes, req.MaxErrorRate = 60, 1, 5 // a step a second

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cs.runCanary(ctx, req)

	svc, _ := fake.GetService(ctx, id)
	if w := svc.WeightedTargets[1].Weight; w != 0 || ctx.Err() != nil {
		t.Fatalf("the canary was not rolled back after a step that failed 50%% of its requests "+
			"(canary weight %d, rollout still running: %v)", w, ctx.Err() != nil)
	}
	var recorded string
	for _, ev := range telemetry.GetCircuitBreakerEvents() {
		if ev.Target == "service "+id+" (canary)" && ev.State == telemetry.CircuitOpen {
			recorded = ev.Reason
		}
	}
	if !strings.Contains(recorded, "50.0% of this step's 100 requests failed") {
		t.Fatalf("the rollback is not on the dashboard's event timeline as the step's rate: %q", recorded)
	}
}

// TestAQuietStepIsNotJudgedOnErrors: a step that served no requests has no
// error rate, so it neither rolls back nor counts as healthy evidence.
func TestAQuietStepIsNotJudgedOnErrors(t *testing.T) {
	quiet := telemetry.GoldenSignals{RequestsTotal: 500, ErrorsTotal: 400}
	if _, breached := stepBreach(&gateonv1.StartCanaryRequest{MaxErrorRate: 5}, quiet, quiet); breached {
		t.Fatal("a step with no traffic was rolled back on the errors before it")
	}
}
