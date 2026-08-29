// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package canary

import (
	"context"
	"time"

	"github.com/google/uuid"
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

// StartCanary starts a background task to gradually shift traffic to target weights.
func (cs *serviceImpl) StartCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) (string, error) {
	taskID := uuid.NewString()

	// Detached from the request so a gradual rollout is not cancelled when this
	// RPC returns, but hung off the process lifetime so it does stop at
	// shutdown. context.Background() gave the first half only.
	//nolint:contextcheck // deliberately the process lifetime, not ctx: a rollout
	// shifts weights over minutes and must survive this call returning.
	go cs.runCanary(cs.lifetime, req)

	return taskID, nil
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

	interval := time.Duration(req.DurationMinutes) * time.Minute / time.Duration(req.Steps)

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

	for i := range int(req.Steps) {
		time.Sleep(interval)

		// Automated Canary Analysis: Evaluate metrics
		metrics := telemetry.GetServiceGoldenSignals(ctx, req.ServiceId)
		if (req.MaxErrorRate > 0 && float32(metrics.ErrorRate) > req.MaxErrorRate) ||
			(req.MaxP99LatencyMs > 0 && metrics.P99LatencyMs > float64(req.MaxP99LatencyMs)) {
			cs.logger.LogWarn("Canary aborted: safety thresholds exceeded. Rolling back.",
				"service_id", req.ServiceId,
				"error_rate", metrics.ErrorRate,
				"max_error_rate", req.MaxErrorRate,
				"p99_latency_ms", metrics.P99LatencyMs,
				"max_p99_latency_ms", req.MaxP99LatencyMs)

			if err := cs.svcService.SaveService(ctx, originalSvc); err != nil {
				cs.logger.LogError("Canary rollback failed", "error", err, "service_id", req.ServiceId)
			}
			return
		}

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
