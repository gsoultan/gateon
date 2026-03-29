package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// CanaryServiceImpl handles automated traffic shifting (Canary) for a service.
type CanaryServiceImpl struct {
	svcService ServiceService
}

// NewCanaryService creates a new CanaryService.
func NewCanaryService(svcService ServiceService) CanaryService {
	return &CanaryServiceImpl{svcService: svcService}
}

// StartCanary starts a background task to gradually shift traffic to target weights.
func (cs *CanaryServiceImpl) StartCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) (string, error) {
	taskID := uuid.NewString()

	// Use background context for the long-running task to survive the API request
	go cs.runCanary(context.Background(), req)

	return taskID, nil
}

func (cs *CanaryServiceImpl) runCanary(ctx context.Context, req *gateonv1.StartCanaryRequest) {
	logger.L.Info().
		Str("service_id", req.ServiceId).
		Int32("duration", req.DurationMinutes).
		Int32("steps", req.Steps).
		Msg("Starting Canary deployment task")

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
		logger.L.Error().Str("service_id", req.ServiceId).Msg("Canary failed: service not found")
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
			logger.L.Error().Str("service_id", req.ServiceId).Msg("Canary aborted: service deleted during deployment")
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
			logger.L.Error().Err(err).Str("service_id", req.ServiceId).Msg("Canary failed to update weights")
			return
		}

		logger.L.Info().
			Str("service_id", req.ServiceId).
			Float64("progress_percent", progress*100).
			Msg("Canary deployment in progress")
	}

	logger.L.Info().Str("service_id", req.ServiceId).Msg("Canary deployment completed successfully")
}
