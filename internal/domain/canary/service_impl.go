package canary

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// serviceImpl handles automated traffic shifting (Canary) for a service.
type serviceImpl struct {
	svcService service.Service
	logger     logger.Logger
}

// NewService creates a new Canary Service.
func NewService(svcService service.Service, l logger.Logger) Service {
	return &serviceImpl{svcService: svcService, logger: l}
}

// StartCanary starts a background task to gradually shift traffic to target weights.
func (cs *serviceImpl) StartCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) (string, error) {
	taskID := uuid.NewString()

	// Use background context for the long-running task to survive the API request
	go cs.runCanary(context.Background(), req)

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

	// Deep copy initial service state for potential rollback
	originalSvc := &gateonv1.Service{
		Id:                  svc.Id,
		Name:                svc.Name,
		LoadBalancerPolicy:  svc.LoadBalancerPolicy,
		HealthCheckPath:     svc.HealthCheckPath,
		BackendType:         svc.BackendType,
		DiscoveryUrl:        svc.DiscoveryUrl,
		TlsClientConfig:     svc.TlsClientConfig,
		HealthCheckPort:     svc.HealthCheckPort,
		HealthCheckProtocol: svc.HealthCheckProtocol,
		HealthCheckType:     svc.HealthCheckType,
	}
	for _, t := range svc.WeightedTargets {
		originalSvc.WeightedTargets = append(originalSvc.WeightedTargets, &gateonv1.Target{
			Url:    t.Url,
			Weight: t.Weight,
		})
	}

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
			var targetWeight int32 = initialWeight
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
