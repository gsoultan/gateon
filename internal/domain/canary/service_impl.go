// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package canary

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/config"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// serviceImpl handles automated traffic shifting (Canary) for a service.
type serviceImpl struct {
	svcService service.Service
	logger     logger.Logger
	lifetime   context.Context
	// readSignals replaces telemetry.GetServiceGoldenSignals in tests; nil in
	// production.
	readSignals func(ctx context.Context, serviceID string) telemetry.GoldenSignals
}

// NewService creates a new Canary Service. lifetime is the process-lifetime
// context; rollouts run detached from the RPC that starts them but must still
// stop when the gateway does.
// rollouts outlive the RPC that starts them and end with the process.
//
//nolint:contextcheck // lifetime is stored, not derived from a caller's context:
func NewService(lifetime context.Context, svcService service.Service, l logger.Logger) Service {
	if lifetime == nil {
		lifetime = context.Background()
	}
	return &serviceImpl{svcService: svcService, logger: l, lifetime: lifetime}
}

// minCanaryInterval is the shortest gap between weight changes.
//
// Each step writes the service and invalidates route chains, and consults
// metrics that do not move faster than this, so anything below it is cost
// without signal.
const minCanaryInterval = time.Second

// ErrNotRunnable reports a canary that cannot shift traffic as asked. Its
// message says why, for the operator who started it.
var ErrNotRunnable = errors.New("canary cannot run")

// StartCanary starts a background task to gradually shift traffic to target weights.
func (cs *serviceImpl) StartCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) (string, error) {
	if err := cs.checkRunnable(ctx, req); err != nil {
		return "", err
	}
	taskID := uuid.NewString()

	// Detached from the request so a gradual rollout is not cancelled when this
	// RPC returns, but hung off the process lifetime so it does stop at
	// shutdown. context.Background() gave the first half only.
	//nolint:contextcheck // deliberately the process lifetime, not ctx: a rollout
	// shifts weights over minutes and must survive this call returning.
	go cs.runCanary(cs.lifetime, req)

	return taskID, nil
}

// checkRunnable refuses, before anything starts, a canary that could not shift
// any traffic. The rollout used to start regardless and find out in its own
// goroutine, after the API had already answered success: a missing service or
// weights naming none of its targets ended at once in the log, and a service
// on a policy that ignores weights -- anything but weighted round robin --
// logged its progress to completion while every request went where it always
// had.
func (cs *serviceImpl) checkRunnable(ctx context.Context, req *gateonv1.StartCanaryRequest) error {
	svc, ok := cs.svcService.GetService(ctx, req.ServiceId)
	if !ok {
		return fmt.Errorf("%w: service %q not found", ErrNotRunnable, req.ServiceId)
	}
	if policy := config.CanonicalLBPolicy(svc.LoadBalancerPolicy); policy != "round_robin" && policy != "weighted_round_robin" {
		return fmt.Errorf("%w: service %q balances with %s, which ignores target weights; "+
			"switch it to round robin to shift traffic by weight", ErrNotRunnable, svc.Id, policy)
	}
	for _, tw := range req.TargetWeights {
		for _, t := range svc.WeightedTargets {
			if t.Url == tw.Url {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: none of the target weights names a target of service %q", ErrNotRunnable, svc.Id)
}

func (cs *serviceImpl) runCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) {
	cs.logger.LogInfo("Starting Canary deployment task",
		"service_id", req.ServiceId,
		"duration", req.DurationMinutes,
		"steps", req.Steps)

	if req.Steps <= 0 {
		req.Steps = 10
	}
	if req.DurationMinutes <= 0 {
		req.DurationMinutes = 1
	}

	total := time.Duration(req.DurationMinutes) * time.Minute
	interval := total / time.Duration(req.Steps)

	// Steps arrives from the request and nothing between the handler and here
	// checks anything but its sign. At Steps=1000000 over one minute the interval
	// is sixty nanoseconds, and every round writes the service to disk and
	// invalidates route chains -- one API call spending the gateway on rewriting
	// its own configuration.
	//
	// The floor is applied to the interval rather than to the step count so the
	// rollout still takes the time the operator asked for; only the number of
	// increments inside it changes. A second is already far below anything
	// useful: GetServiceGoldenSignals is what each step consults, and error rate
	// and p99 do not move meaningfully faster than that.
	if interval < minCanaryInterval {
		interval = minCanaryInterval
		req.Steps = int32(total / minCanaryInterval)
		if req.Steps < 1 {
			req.Steps = 1
		}
	}

	// Get initial service state
	svc, ok := cs.svcService.GetService(ctx, req.ServiceId)
	if !ok {
		cs.logger.LogError("Canary failed: service not found", "service_id", req.ServiceId)
		return
	}

	// Snapshot for rollback. See snapshotService: this must copy the whole
	// message, not a list of fields someone remembered.
	originalSvc := snapshotService(svc)

	// Store initial weights to interpolate from
	initialWeights := make(map[string]int32)
	for _, t := range svc.WeightedTargets {
		initialWeights[t.Url] = t.Weight
	}

	// Each step is judged on its own traffic: the counts at its start are the
	// baseline its errors are measured against (see stepBreach).
	prev := cs.signals(ctx, req.ServiceId)

	for i := range int(req.Steps) {
		// Not time.Sleep. StartCanary detaches this onto the process lifetime and
		// says it stops at shutdown; a sleep no cancellation can interrupt is what
		// made that untrue. A rollout spread over an hour sat in an
		// uninterruptible wait of minutes while the process drained, then wrote
		// one more weight change on its way out.
		select {
		case <-ctx.Done():
			cs.logger.LogInfo("Canary stopped: context cancelled",
				"service_id", req.ServiceId, "completed_steps", i)
			return
		case <-time.After(interval):
		}

		// Automated Canary Analysis: judge the step just served.
		cur := cs.signals(ctx, req.ServiceId)
		if reason, breached := stepBreach(req, prev, cur); breached {
			cs.rollBack(ctx, originalSvc, reason)
			return
		}
		prev = cur

		progress := float64(i+1) / float64(req.Steps)

		// Refresh service state to ensure we don't overwrite other changes
		currentSvc, ok := cs.svcService.GetService(ctx, req.ServiceId)
		if !ok {
			cs.logger.LogError("Canary aborted: service deleted during deployment", "service_id", req.ServiceId)
			return
		}

		for _, target := range currentSvc.WeightedTargets {
			initialWeight := initialWeights[target.Url]

			// Find target weight in request
			var targetWeight = initialWeight
			found := false
			for _, tw := range req.TargetWeights {
				if tw.Url == target.Url {
					targetWeight = tw.Weight
					found = true
					break
				}
			}

			if found {
				// Linear interpolation
				diff := float64(targetWeight) - float64(initialWeight)
				target.Weight = int32(float64(initialWeight) + diff*progress)
			}
		}

		if err := cs.svcService.SaveService(ctx, currentSvc); err != nil {
			cs.logger.LogError("Canary failed to update weights", "error", err, "service_id", req.ServiceId)
			return
		}

		cs.logger.LogInfo("Canary deployment in progress",
			"service_id", req.ServiceId,
			"progress_percent", progress*100)
	}

	cs.logger.LogInfo("Canary deployment completed successfully", "service_id", req.ServiceId)
}

// stepBreach judges one step against the request's limits and says why it
// failed. The error rate is the step's own: errors over requests since the
// step began. It was the service's lifetime rate, so a long healthy history
// diluted a step failing half its requests below any threshold -- 800 earlier
// requests already pulled a 50%-failing step to 10%. A step that served
// nothing is not judged on errors. p99 is still read from the service's
// lifetime latency histogram: a per-step percentile needs the histogram's
// buckets, which the golden signals do not carry.
func stepBreach(req *gateonv1.StartCanaryRequest, prev, cur telemetry.GoldenSignals) (string, bool) {
	if served := cur.RequestsTotal - prev.RequestsTotal; req.MaxErrorRate > 0 && served > 0 {
		rate := (cur.ErrorsTotal - prev.ErrorsTotal) / served * 100
		if rate > float64(req.MaxErrorRate) {
			return fmt.Sprintf("canary rolled back: %.1f%% of this step's %.0f requests failed (max %.1f%%)",
				rate, served, req.MaxErrorRate), true
		}
	}
	if req.MaxP99LatencyMs > 0 && cur.P99LatencyMs > float64(req.MaxP99LatencyMs) {
		return fmt.Sprintf("canary rolled back: p99 latency %.0f ms (max %d ms)",
			cur.P99LatencyMs, req.MaxP99LatencyMs), true
	}
	return "", false
}

// rollBack restores the service as it was before the rollout and says so
// where the dashboard shows it: the Circuit Breaker page's event timeline,
// under the service. A rollback was a server log line only, and the wizard's
// last word was "Canary Started".
func (cs *serviceImpl) rollBack(ctx context.Context, original *gateonv1.Service, reason string) {
	cs.logger.LogWarn("Canary aborted: safety thresholds exceeded. Rolling back.",
		"service_id", original.GetId(), "reason", reason)
	if err := cs.svcService.SaveService(ctx, original); err != nil {
		cs.logger.LogError("Canary rollback failed", "error", err, "service_id", original.GetId())
		reason += "; restoring the original weights FAILED: " + err.Error()
	}
	telemetry.RecordCircuitBreakerEvent("service "+original.GetId()+" (canary)", telemetry.CircuitOpen, reason)
}

// signals reads the service's golden signals; a test may substitute its own.
func (cs *serviceImpl) signals(ctx context.Context, serviceID string) telemetry.GoldenSignals {
	if cs.readSignals != nil {
		return cs.readSignals(ctx, serviceID)
	}
	return telemetry.GetServiceGoldenSignals(ctx, serviceID)
}

// snapshotService deep-copies a service so a failed canary can be rolled back
// to exactly what was there before.
//
// It uses proto.Clone rather than listing fields. The previous version was a
// hand-written struct literal naming ten of the Service's fifteen fields and
// two of Target's five, so a rollback silently dropped
// l4_health_check_interval_ms, l4_health_check_timeout_ms,
// l4_udp_session_timeout_s, l4_proxy_protocol, and every target's protocol,
// proxy_protocol_enabled and proxy_protocol_version.
//
// Which is the worst possible place for that. Rollback is the safety path: it
// runs when error rate or p99 has already breached, and it was resetting L4
// timeouts to zero and switching PROXY protocol off, so the backend stopped
// seeing real client addresses at the exact moment someone was reading the
// logs to find out what went wrong.
//
// A hand-maintained copy of a generated message rots by construction -- fields
// 7 to 10 and Target 4 to 5 were added after this was written, and nothing
// pointed at it. proto.Clone cannot fall behind the schema.
func snapshotService(svc *gateonv1.Service) *gateonv1.Service {
	if svc == nil {
		return nil
	}
	cloned, ok := proto.Clone(svc).(*gateonv1.Service)
	if !ok {
		// Cannot happen: Clone returns the same concrete type it was given.
		return nil
	}
	return cloned
}
