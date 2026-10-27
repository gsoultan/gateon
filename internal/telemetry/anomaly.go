// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package telemetry

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/security/mitigation"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Severities anomaly findings are filed with. They are kind.SeverityHigh and
// kind.SeverityMedium, the vocabulary the correlation engine, SIEM and
// dashboard read; telemetry cannot import kind, which imports it.
const (
	severityHigh   = "high"
	severityMedium = "medium"
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

	// Non-positive, not just zero: the API stores a negative value as given,
	// and time.NewTicker panics on it on a goroutine with no recover.
	interval := time.Duration(ad.config.CheckIntervalSeconds)
	if interval <= 0 {
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

	// 3. Brute Force Detection: refused credential attempts, not every
	// 401 and 403 (credentialRefusal)
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

// The failure rate brute force fires above at the default sensitivity. The
// dashboard's Sensitivity runs from 0 to 1 and ships at 0.5.
const (
	defaultSensitivity      = 0.5
	bruteForceRateAtDefault = 0.75
)

// CredentialGuessMinRefusals is how many refused credential attempts an
// address needs before anything may be held against it as guessing: the
// analysis engine's harm rule (harmMinAuthFailures) and the brute-force check
// here read this one number.
//
// The brute-force check used to act on six. Its rate bar already asks that most
// of an address's traffic be refused logins, but six refusals in one interval
// is a person who has forgotten a password, or an app retrying a stale one, and
// it earned a shun -- and with it decisive attack evidence (AttackEvidenceWeight)
// that fed every other control -- for what the analysis engine judges not yet
// harmful. Below the bar the detection is recorded for the operator and held
// against nobody, as a shared address's exploit-scan count is.
const CredentialGuessMinRefusals = 10

// bruteForceRateThreshold is the auth-failure rate above which an address is
// reported, scaled inversely with sensitivity as the exploit, error-rate and
// latency bars are: a higher setting lowers the bar, and 0 switches it off.
//
// It used to be Sensitivity*1.5, which ran the other way. The default kept its
// 0.75, but from 0.67 up the bar passed 1.0 -- a rate no client can reach -- so
// the settings an operator chooses to catch more stopped brute-force detection
// altogether, while 0 flagged any address with six failed logins.
func (ad *AnomalyDetector) bruteForceRateThreshold() float64 {
	return bruteForceRateAtDefault * defaultSensitivity / ad.config.Sensitivity
}

func (ad *AnomalyDetector) checkBruteForce(ctx context.Context, now time.Time) {
	stats := ad.aggregator.GetIPStats(10) // IPs with at least 10 requests
	threshold := ad.bruteForceRateThreshold()
	for _, s := range stats {
		if s.Requests == 0 {
			continue
		}
		rate := s.AuthFail / s.Requests
		if rate > threshold && s.AuthFail > 5 {
			ad.recordBruteForce(ctx, s, rate, now)
		}
	}
}

// recordBruteForce records a brute force from s, failing credential attempts
// at rate, and throttles or shuns it once its refusals reach
// CredentialGuessMinRefusals.
func (ad *AnomalyDetector) recordBruteForce(ctx context.Context, s IPResult, rate float64, now time.Time) {
	logger.L.LogWarn("ANOMALY DETECTED: Potential brute force detected from IP",
		"ip", s.IP,
		"auth_failure_rate", rate)

	details := fmt.Sprintf("Potential brute force detected: auth failure rate %.2f", rate)
	guessing := s.AuthFail >= CredentialGuessMinRefusals
	severity, action := severityMedium, ""
	switch {
	case !guessing:
		details = fmt.Sprintf("%s, %.0f refused attempts: under the %d the harm rule asks for",
			details, s.AuthFail, CredentialGuessMinRefusals)
		action = ActionFlagged
	case rate > 0.8:
		// Shun for a critical threat.
		severity = "critical"
		action = ad.shun(ctx, s.IP, details)
	default:
		action = ad.throttle(s.IP, 1*time.Second, "Anomaly detection: brute force") // Limit to 1 req/sec
	}
	RecordSecurityThreat(SecurityThreat{
		ID:          fmt.Sprintf("anomaly-bruteforce-%s-%d", s.IP, now.Unix()),
		Type:        "brute_force_attempt",
		SourceIP:    s.IP,
		Score:       rate * 100,
		Details:     details,
		Time:        now,
		Category:    "brute_force",
		Severity:    severity,
		ActionTaken: action,
		Observed:    !guessing,
	})
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

		scanning := blockRate > thresholdRate && s.WafBlocks > absoluteThreshold
		if !scanning && s.WafBlocks <= absoluteThreshold*10 {
			continue
		}
		logger.L.LogWarn("ANOMALY DETECTED: High rate of WAF blocks detected from IP",
			"ip", s.IP,
			"waf_blocks", s.WafBlocks,
			"block_rate", fmt.Sprintf("%.2f%%", blockRate*100))

		details := fmt.Sprintf("High rate of WAF blocks: %.0f blocks", s.WafBlocks)
		severity, score, action := severityHigh, math.Min(100, s.WafBlocks*5), ""
		switch {
		case !scanning:
			// Many blocks that are a small share of what the address sends.
			// An address that sends that much is an office, a CGNAT pool or
			// a VPN exit, and a block rate under the bar is one client of it
			// attacking while the rest browse: the WAF refuses each attack
			// as it arrives, and limiting the address limits the rest. The
			// count used to throttle it in the kernel on its own, as the
			// harm rule the analysis engine applies (harmMinAttackShare)
			// never would. Recorded for the operator and held against
			// nobody (ADR 0059), as a detection a control let through is.
			details = fmt.Sprintf("%s, %.1f%% of the address's requests: a shared address, not a scanner",
				details, blockRate*100)
			action = ActionFlagged
		case blockRate > 0.5 && s.WafBlocks > absoluteThreshold*5:
			severity, score = "critical", math.Min(100, s.WafBlocks*10)
			action = ad.shun(ctx, s.IP, details)
		default:
			action = ad.throttle(s.IP, 500*time.Millisecond, "Anomaly detection: exploit scanning") // Limit to 2 req/sec
		}
		RecordSecurityThreat(SecurityThreat{
			ID:          fmt.Sprintf("anomaly-exploit-%s-%d", s.IP, now.Unix()),
			Type:        "exploit_scan",
			SourceIP:    s.IP,
			Score:       score,
			Details:     details,
			Time:        now,
			Category:    "exploit_scanning",
			Severity:    severity,
			ActionTaken: action,
			Observed:    !scanning,
		})
	}
}

// shun blocks an address for the detector and returns the ActionTaken that
// describes what actually happened.
//
// This used to call the eBPF manager's ShunIP, discard the error, and record
// "shunned" whatever the outcome. The manager the detector is given is the
// eBPF Holder, whose ShunIP answers nil when eBPF is disabled -- the default,
// and the only possibility off Linux -- and the manager's own fails when the
// program is not loaded. Either way the threat was counted as mitigated and
// shown as blocked while nothing refused the source.
//
// ShunAutomatically is the block the request path reads on every entrypoint
// and route; it survives a restart, appears on the mitigation list with when
// it lifts, and is leased in the kernel as well when eBPF is running. It
// lapses (ADR 0031): fifteen minutes the first time, doubling up to a day for
// an address that comes back soon after. An address the operator allowlisted
// or released within the hold is flagged instead of blocked, as the other
// automatic paths treat them.
func (ad *AnomalyDetector) shun(ctx context.Context, ip, reason string) string {
	res, err := ShunAutomaticallyContext(ctx, ip, "Anomaly detection: "+reason)
	if err != nil {
		logger.L.LogError("anomaly shun did not persist; the source is not blocked", "ip", ip, "error", err)
		return ActionDetected
	}
	if !res.Shunned() {
		return ActionFlagged
	}
	return ActionShunned
}

// throttle installs an adaptive kernel rate limit and returns the ActionTaken
// that describes what actually happened. Only an attached eBPF program can
// throttle, and the Holder answers nil when there is none, so success is read
// from the attachment rather than from the call; without one the threat is
// flagged for review rather than recorded as throttled.
func (ad *AnomalyDetector) throttle(ip string, interval time.Duration, reason string) string {
	if ad.ebpfManager == nil || mitigation.IsAllowlisted(ip) {
		return ActionFlagged
	}
	if st, err := ad.ebpfManager.GetMapStats(); err != nil || !st.Attached {
		return ActionFlagged
	}
	if err := ebpf.SetAdaptiveRateLimitFor(ad.ebpfManager, ip, interval, reason); err != nil {
		logger.L.LogWarn("anomaly throttle was not applied", "ip", ip, "error", err)
		return ActionFlagged
	}
	return ActionThrottled
}

// errorRateWindow is the stretch of recent traffic the error-rate check judges
// against the hour before it.
const errorRateWindow = 5 * time.Minute

func (ad *AnomalyDetector) checkErrorRate(ctx context.Context, now time.Time) {
	currentErrors := ad.aggregator.GetRate("errors", errorRateWindow)
	currentRequests := ad.aggregator.GetRate("requests", errorRateWindow)

	if currentRequests < 1 { // Not enough traffic
		return
	}

	// Baseline: last 1 hour. Only the request rate is needed — it gates whether
	// there is enough traffic for a deviation to mean anything. The error ratio
	// that used to be computed here, floor and all, was never read: detection is
	// the Z-score below, not a ratio threshold.
	baselineRequests := ad.aggregator.GetRate("requests", 1*time.Hour)

	if baselineRequests > 5 {
		z := ad.aggregator.errorZScore(currentErrors, errorRateWindow)
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
				Severity:    severityHigh,
				ActionTaken: ActionFlagged,
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
		z := ad.aggregator.latencyZScore(currentP99)
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
				Severity:    severityMedium,
				ActionTaken: ActionFlagged,
			})
		}
	}
}
