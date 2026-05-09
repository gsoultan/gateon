package telemetry

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

// AnomalyDetector monitors metrics and detects unusual patterns using ML-inspired thresholds.
type AnomalyDetector struct {
	config      *gateonv1.AnomalyDetectionConfig
	api         v1.API
	ebpfManager ebpf.Manager
}

// NewAnomalyDetector creates a new detector with the given configuration.
func NewAnomalyDetector(conf *gateonv1.AnomalyDetectionConfig, ebpfManager ebpf.Manager) (*AnomalyDetector, error) {
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
		config:      conf,
		api:         v1.NewAPI(client),
		ebpfManager: ebpfManager,
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

	logger.L.LogInfo("Anomaly detection service started",
		"prometheus_url", ad.config.PrometheusUrl,
		"interval", interval*time.Second)

	ticker := time.NewTicker(interval * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L.LogInfo("Anomaly detection service stopping")
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

	// 3. Brute Force Detection (401/403 spikes)
	if ad.config.GetEnableBruteForceDetection() {
		ad.checkBruteForce(ctx, now)
	}

	// 4. Exploit Scanning Detection (WAF block spikes)
	if ad.config.GetEnableExploitDetection() {
		ad.checkExploitScanning(ctx, now)
	}
}

func (ad *AnomalyDetector) checkBruteForce(ctx context.Context, now time.Time) {
	// Detect if 401/403 rate is higher than sensitivity per IP
	query := `sum(rate(gateon_requests_total{status_code=~"401|403"}[5m])) by (source_ip) / sum(rate(gateon_requests_total[5m])) by (source_ip)`

	val, _, err := ad.api.Query(ctx, query, now)
	if err != nil {
		return
	}

	if vector, ok := val.(model.Vector); ok {
		for _, v := range vector {
			rate := float64(v.Value)
			if rate > ad.config.Sensitivity*1.5 {
				ip := string(v.Metric["source_ip"])
				logger.L.LogWarn("ANOMALY DETECTED: Potential brute force detected from IP",
					"ip", ip,
					"auth_failure_rate", rate)

				// Auto-shun at eBPF level for critical threat
				if ad.ebpfManager != nil && rate > 0.8 {
					_ = ad.ebpfManager.ShunIP(ip)
					RecordSecurityThreat(SecurityThreat{
						ID:          fmt.Sprintf("anomaly-bruteforce-%s-%d", ip, now.Unix()),
						Type:        "anomaly_detected",
						SourceIP:    ip,
						Score:       rate * 100,
						Details:     fmt.Sprintf("Potential brute force detected: auth failure rate %.2f", rate),
						Time:        now,
						Category:    "brute_force",
						Severity:    "critical",
						ActionTaken: "shunned",
					})
				} else {
					RecordSecurityThreat(SecurityThreat{
						ID:          fmt.Sprintf("anomaly-bruteforce-%s-%d", ip, now.Unix()),
						Type:        "anomaly_detected",
						SourceIP:    ip,
						Score:       rate * 100,
						Details:     fmt.Sprintf("Potential brute force detected: auth failure rate %.2f", rate),
						Time:        now,
						Category:    "brute_force",
						Severity:    "medium",
						ActionTaken: "flagged",
					})
				}
			}
		}
	}
}

func (ad *AnomalyDetector) checkExploitScanning(ctx context.Context, now time.Time) {
	// Detect unusual spike in WAF blocks per IP
	query := `sum(rate(gateon_middleware_waf_blocked_total[5m])) by (source_ip)`

	val, _, err := ad.api.Query(ctx, query, now)
	if err != nil {
		return
	}

	if vector, ok := val.(model.Vector); ok {
		for _, v := range vector {
			rate := float64(v.Value)
			threshold := 0.5 / ad.config.Sensitivity
			if rate > threshold {
				ip := string(v.Metric["source_ip"])
				logger.L.LogWarn("ANOMALY DETECTED: High rate of WAF blocks detected from IP",
					"ip", ip,
					"waf_block_rate", rate)

				if ad.ebpfManager != nil && rate > threshold*2 {
					_ = ad.ebpfManager.ShunIP(ip)
					RecordSecurityThreat(SecurityThreat{
						ID:          fmt.Sprintf("anomaly-exploit-%s-%d", ip, now.Unix()),
						Type:        "anomaly_detected",
						SourceIP:    ip,
						Score:       math.Min(100, rate*10),
						Details:     fmt.Sprintf("High rate of WAF blocks: %.2f req/s", rate),
						Time:        now,
						Category:    "exploit_scanning",
						Severity:    "critical",
						ActionTaken: "shunned",
					})
				} else {
					RecordSecurityThreat(SecurityThreat{
						ID:          fmt.Sprintf("anomaly-exploit-%s-%d", ip, now.Unix()),
						Type:        "anomaly_detected",
						SourceIP:    ip,
						Score:       math.Min(100, rate*5),
						Details:     fmt.Sprintf("High rate of WAF blocks: %.2f req/s", rate),
						Time:        now,
						Category:    "exploit_scanning",
						Severity:    "high",
						ActionTaken: "flagged",
					})
				}
			}
		}
	}
}

func (ad *AnomalyDetector) checkErrorRate(ctx context.Context, now time.Time) {
	// Detect if 5xx rate is significantly higher than historical baseline (seasonal)
	// Compare 5m rate with 1h predicted rate from last week's data (simulated with predict_linear)
	query := `
		sum(rate(gateon_requests_total{status_code=~"5.."}[5m])) 
		/ 
		(sum(predict_linear(rate(gateon_requests_total{status_code=~"5.."}[1h])[1w:1h], 3600)) + 0.01)
	`

	val, _, err := ad.api.Query(ctx, query, now)
	if err != nil {
		logger.L.LogDebug("failed to query error rate for anomaly detection", "error", err)
		return
	}

	if vector, ok := val.(model.Vector); ok && len(vector) > 0 {
		ratio := float64(vector[0].Value)
		// If current rate is > 3x the predicted baseline, it's an anomaly
		if ratio > 3.0/ad.config.Sensitivity {
			logger.L.LogWarn("ANOMALY DETECTED: 5xx error rate is significantly higher than historical baseline",
				"deviation_ratio", ratio,
				"sensitivity", ad.config.Sensitivity)
		}
	}
}

func (ad *AnomalyDetector) checkLatency(ctx context.Context, now time.Time) {
	// Detect if P99 latency deviates from Holt-Winters predicted baseline
	query := `
		histogram_quantile(0.99, sum(rate(gateon_request_duration_seconds_bucket[5m])) by (le))
		/
		(holt_winters(histogram_quantile(0.99, sum(rate(gateon_request_duration_seconds_bucket[1h])) by (le))[1d:5m], 0.5, 0.5) + 0.001)
	`

	val, _, err := ad.api.Query(ctx, query, now)
	if err != nil {
		logger.L.LogDebug("failed to query latency for anomaly detection", "error", err)
		return
	}

	if vector, ok := val.(model.Vector); ok && len(vector) > 0 {
		ratio := float64(vector[0].Value)
		// If current P99 is > 2x the predicted baseline
		if ratio > 2.0/ad.config.Sensitivity {
			logger.L.LogWarn("ANOMALY DETECTED: Unusually high P99 latency compared to historical baseline",
				"deviation_ratio", ratio,
				"sensitivity", ad.config.Sensitivity)
		}
	}
}
