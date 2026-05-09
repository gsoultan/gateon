package canary

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/domain/service"
	"github.com/gsoultan/gateon/internal/logger"
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

	// Store initial weights to interpolate from
	initialWeights := make(map[string]int32)
	for _, t := range svc.WeightedTargets {
		initialWeights[t.Url] = t.Weight
	}

	for i := range int(req.Steps) {
		time.Sleep(interval)

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
