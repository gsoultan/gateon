package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// AnomalyDetector monitors metrics and detects unusual patterns using ML-inspired thresholds.
type AnomalyDetector struct {
	config *gateonv1.AnomalyDetectionConfig
	api    v1.API
}

// NewAnomalyDetector creates a new detector with the given configuration.
func NewAnomalyDetector(conf *gateonv1.AnomalyDetectionConfig) (*AnomalyDetector, error) {
	if conf.PrometheusUrl == "" {
		return nil, fmt.Errorf("prometheus url is required for anomaly detection")
	}

	client, err := api.NewClient(api.Config{
		Address: conf.PrometheusUrl,
	})
	if err != nil {
		return nil, fmt.Errorf("create prometheus client: %w", err)
	}

	return &AnomalyDetector{
		config: conf,
		api:    v1.NewAPI(client),
	}, nil
}

// Start runs the detection loop.
func (ad *AnomalyDetector) Start(ctx context.Context) {
	if !ad.config.Enabled {
		return
	}

	interval := time.Duration(ad.config.CheckIntervalSeconds)
	if interval == 0 {
		interval = 60
	}

	logger.L.Info().
		Str("prometheus_url", ad.config.PrometheusUrl).
		Dur("interval", interval*time.Second).
		Msg("Anomaly detection service started")

	ticker := time.NewTicker(interval * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L.Info().Msg("Anomaly detection service stopping")
			return
		case t := <-ticker.C:
			ad.runChecks(ctx, t)
		}
	}
}

func (ad *AnomalyDetector) runChecks(ctx context.Context, now time.Time) {
	// 1. Error Rate Spike Detection
	ad.checkErrorRate(ctx, now)

	// 2. Latency Anomaly Detection (P99)
	ad.checkLatency(ctx, now)
}

func (ad *AnomalyDetector) checkErrorRate(ctx context.Context, now time.Time) {
	// Detect if 5xx rate is higher than sensitivity (e.g. 0.05 = 5%)
	query := `sum(rate(gateon_http_requests_total{status=~"5.."}[5m])) / sum(rate(gateon_http_requests_total[5m]))`

	val, _, err := ad.api.Query(ctx, query, now)
	if err != nil {
		logger.L.Debug().Err(err).Msg("failed to query error rate for anomaly detection")
		return
	}

	if vector, ok := val.(model.Vector); ok && len(vector) > 0 {
		rate := float64(vector[0].Value)
		if rate > ad.config.Sensitivity {
			logger.L.Warn().
				Float64("error_rate", rate).
				Float64("threshold", ad.config.Sensitivity).
				Msg("ANOMALY DETECTED: High 5xx error rate detected across entrypoints")
		}
	}
}

func (ad *AnomalyDetector) checkLatency(ctx context.Context, now time.Time) {
	// Detect if P99 latency is significantly higher than historical average (Z-score like)
	// For simplicity, we compare with a static high threshold scaled by sensitivity
	// In a real ML model, we'd use Prometheus HOLT_WINTERS or similar functions.

	query := `histogram_quantile(0.99, sum(rate(gateon_http_request_duration_seconds_bucket[5m])) by (le))`

	val, _, err := ad.api.Query(ctx, query, now)
	if err != nil {
		logger.L.Debug().Err(err).Msg("failed to query latency for anomaly detection")
		return
	}

	if vector, ok := val.(model.Vector); ok && len(vector) > 0 {
		p99 := float64(vector[0].Value)
		// Assume > 2s is high, scaled by sensitivity (lower sensitivity means higher threshold)
		threshold := 2.0 / (ad.config.Sensitivity * 2)
		if p99 > threshold {
			logger.L.Warn().
				Float64("p99_latency_seconds", p99).
				Float64("threshold_seconds", threshold).
				Msg("ANOMALY DETECTED: Unusually high P99 latency detected")
		}
	}
}
