package telemetry

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AnomalyDetector monitors metrics and detects unusual patterns using ML-inspired thresholds.
// It uses a local aggregator instead of an external Prometheus server.
type AnomalyDetector struct {
	config      *gateonv1.AnomalyDetectionConfig
	ebpfManager ebpf.Manager
	aggregator  *LocalMetricsAggregator
}

// NewAnomalyDetector creates a new detector with the given configuration.
func NewAnomalyDetector(conf *gateonv1.AnomalyDetectionConfig, ebpfManager ebpf.Manager) (*AnomalyDetector, error) {
	return &AnomalyDetector{
		config:      conf,
		ebpfManager: ebpfManager,
		aggregator:  GetAggregator(),
	}, nil
}

// Start runs the detection loop.
func (ad *AnomalyDetector) Start(ctx context.Context) {
	if !ad.config.Enabled {
		return
	}

	// Start the aggregator's collection loop
	go ad.aggregator.Start(ctx)

	interval := time.Duration(ad.config.CheckIntervalSeconds)
	if interval == 0 {
		interval = 60
	}

	logger.L.LogInfo("Anomaly detection service started (local mode)",
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

	// Reset IP stats after each check interval to avoid double counting across intervals
	ad.aggregator.ResetIPStats()
}

func (ad *AnomalyDetector) checkBruteForce(ctx context.Context, now time.Time) {
	stats := ad.aggregator.GetIPStats(10) // IPs with at least 10 requests
	for _, s := range stats {
		if s.Requests == 0 {
			continue
		}
		rate := s.AuthFail / s.Requests
		if rate > ad.config.Sensitivity*1.5 && s.AuthFail > 5 {
			logger.L.LogWarn("ANOMALY DETECTED: Potential brute force detected from IP",
				"ip", s.IP,
				"auth_failure_rate", rate)

			// Auto-shun at eBPF level for critical threat
			if ad.ebpfManager != nil && rate > 0.8 {
				_ = ad.ebpfManager.ShunIP(s.IP)
				RecordSecurityThreat(SecurityThreat{
					ID:          fmt.Sprintf("anomaly-bruteforce-%s-%d", s.IP, now.Unix()),
					Type:        "brute_force_attempt",
					SourceIP:    s.IP,
					Score:       rate * 100,
					Details:     fmt.Sprintf("Potential brute force detected: auth failure rate %.2f", rate),
					Time:        now,
					Category:    "brute_force",
					Severity:    "critical",
					ActionTaken: "shunned",
				})
			} else {
				RecordSecurityThreat(SecurityThreat{
					ID:          fmt.Sprintf("anomaly-bruteforce-%s-%d", s.IP, now.Unix()),
					Type:        "brute_force_attempt",
					SourceIP:    s.IP,
					Score:       rate * 100,
					Details:     fmt.Sprintf("Potential brute force detected: auth failure rate %.2f", rate),
					Time:        now,
					Category:    "brute_force",
					Severity:    "medium",
					ActionTaken: "throttled",
				})
				if ad.ebpfManager != nil {
					_ = ad.ebpfManager.SetAdaptiveRateLimit(s.IP, 1*time.Second) // Limit to 1 req/sec
				}
			}
		}
	}
}

func (ad *AnomalyDetector) checkExploitScanning(ctx context.Context, now time.Time) {
	stats := ad.aggregator.GetIPStats(0)
	// Base threshold: blocks per check interval.
	// We also consider the ratio of blocks to total requests from that IP.
	for _, s := range stats {
		if s.Requests == 0 {
			continue
		}
		blockRate := s.WafBlocks / s.Requests
		// High sensitivity: blockRate > 5% AND at least some absolute blocks
		// Low sensitivity: blockRate > 20%
		thresholdRate := 0.1 * (1.0 / ad.config.Sensitivity)
		absoluteThreshold := 5.0 * (1.0 / ad.config.Sensitivity)

		if (blockRate > thresholdRate && s.WafBlocks > absoluteThreshold) || s.WafBlocks > absoluteThreshold*10 {
			logger.L.LogWarn("ANOMALY DETECTED: High rate of WAF blocks detected from IP",
				"ip", s.IP,
				"waf_blocks", s.WafBlocks,
				"block_rate", fmt.Sprintf("%.2f%%", blockRate*100))

			if ad.ebpfManager != nil && blockRate > 0.5 && s.WafBlocks > absoluteThreshold*5 {
				_ = ad.ebpfManager.ShunIP(s.IP)
				RecordSecurityThreat(SecurityThreat{
					ID:          fmt.Sprintf("anomaly-exploit-%s-%d", s.IP, now.Unix()),
					Type:        "exploit_scan",
					SourceIP:    s.IP,
					Score:       math.Min(100, s.WafBlocks*10),
					Details:     fmt.Sprintf("High rate of WAF blocks: %.0f blocks", s.WafBlocks),
					Time:        now,
					Category:    "exploit_scanning",
					Severity:    "critical",
					ActionTaken: "shunned",
				})
			} else {
				RecordSecurityThreat(SecurityThreat{
					ID:          fmt.Sprintf("anomaly-exploit-%s-%d", s.IP, now.Unix()),
					Type:        "exploit_scan",
					SourceIP:    s.IP,
					Score:       math.Min(100, s.WafBlocks*5),
					Details:     fmt.Sprintf("High rate of WAF blocks: %.0f blocks", s.WafBlocks),
					Time:        now,
					Category:    "exploit_scanning",
					Severity:    "high",
					ActionTaken: "throttled",
				})
				if ad.ebpfManager != nil {
					_ = ad.ebpfManager.SetAdaptiveRateLimit(s.IP, 500*time.Millisecond) // Limit to 2 req/sec
				}
			}
		}
	}
}

func (ad *AnomalyDetector) checkErrorRate(ctx context.Context, now time.Time) {
	currentErrors := ad.aggregator.GetRate("errors", 5*time.Minute)
	currentRequests := ad.aggregator.GetRate("requests", 5*time.Minute)

	if currentRequests < 1 { // Not enough traffic
		return
	}

	// Baseline: last 1 hour
	baselineErrors := ad.aggregator.GetRate("errors", 1*time.Hour)
	baselineRequests := ad.aggregator.GetRate("requests", 1*time.Hour)

	if baselineRequests > 5 {
		baselineRate := baselineErrors / baselineRequests
		// Avoid division by zero and handle very low baseline
		if baselineRate < 0.01 {
			baselineRate = 0.01
		}

		z := ad.aggregator.StatsErrors.ZScore(currentErrors)
		// If Z-Score is > 3.0 (standard statistical anomaly threshold)
		if z > 3.0/ad.config.Sensitivity && currentErrors > 5 {
			logger.L.LogWarn("ANOMALY DETECTED: 5xx error rate is statistically anomalous",
				"current_rate", fmt.Sprintf("%.2f eps", currentErrors),
				"z_score", fmt.Sprintf("%.2f", z))

			RecordSecurityThreat(SecurityThreat{
				ID:          fmt.Sprintf("anomaly-error-rate-%d", now.Unix()),
				Type:        "error_rate_spike",
				Score:       math.Min(100, z*20),
				Details:     fmt.Sprintf("Error rate spike detected: Z-Score %.2f (Current %.2f eps)", z, currentErrors),
				Time:        now,
				Category:    "service_instability",
				Severity:    "high",
				ActionTaken: "flagged",
			})
		}
	}
}

func (ad *AnomalyDetector) checkLatency(ctx context.Context, now time.Time) {
	currentP99 := ad.aggregator.GetP99Latency(5 * time.Minute)
	if currentP99 == 0 {
		return
	}

	// Baseline: last 1 hour
	baselineP99 := ad.aggregator.GetP99Latency(1 * time.Hour)

	if baselineP99 > 0 {
		z := ad.aggregator.StatsLatency.ZScore(currentP99)
		// If Z-Score is > 3.0
		if z > 3.0/ad.config.Sensitivity && currentP99 > 0.5 { // ignore spikes below 500ms
			logger.L.LogWarn("ANOMALY DETECTED: P99 latency is statistically anomalous",
				"current_p99", fmt.Sprintf("%.2f s", currentP99),
				"z_score", fmt.Sprintf("%.2f", z))

			RecordSecurityThreat(SecurityThreat{
				ID:          fmt.Sprintf("anomaly-latency-%d", now.Unix()),
				Type:        "latency_spike",
				Score:       math.Min(100, z*25),
				Details:     fmt.Sprintf("High latency spike detected: Z-Score %.2f (Current %.2fs)", z, currentP99),
				Time:        now,
				Category:    "latency_spike",
				Severity:    "medium",
				ActionTaken: "flagged",
			})
		}
	}
}
