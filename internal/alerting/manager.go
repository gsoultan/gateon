// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/gateon/internal/ebpf"
	"github.com/gsoultan/gateon/internal/httputil"
	"github.com/gsoultan/gateon/internal/logger"
	"github.com/gsoultan/gateon/internal/telemetry"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// AlertingManager handles security alerts and playbooks.
type AlertingManager struct {
	mu          sync.RWMutex
	config      *gateonv1.AlertingConfig
	dispatchers map[string]Dispatcher
	ebpfManager ebpf.Manager
}

// Dispatcher is the interface for alert delivery.
type Dispatcher interface {
	Send(ctx context.Context, threat telemetry.SecurityThreat) error
}

var (
	manager *AlertingManager
	once    sync.Once
)

// Init initializes the global AlertingManager.
func Init(cfg *gateonv1.AlertingConfig, em ebpf.Manager) {
	once.Do(func() {
		manager = &AlertingManager{
			config:      cfg,
			dispatchers: make(map[string]Dispatcher),
			ebpfManager: em,
		}
		manager.reconfigure()
	})
}

// UpdateConfig updates the manager with new configuration.
func UpdateConfig(cfg *gateonv1.AlertingConfig, em ebpf.Manager) {
	if manager == nil {
		Init(cfg, em)
		return
	}
	manager.mu.Lock()
	manager.config = cfg
	if em != nil {
		manager.ebpfManager = em
	}
	manager.mu.Unlock()
	manager.reconfigure()
}

func (m *AlertingManager) reconfigure() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.config == nil || !m.config.Enabled {
		m.dispatchers = make(map[string]Dispatcher)
		return
	}

	newDispatchers := make(map[string]Dispatcher)
	for _, d := range m.config.Dispatchers {
		switch d.Type {
		case "slack":
			newDispatchers[d.Id] = NewSlackDispatcher(d.WebhookUrl, d.SlackChannel)
		case "discord":
			newDispatchers[d.Id] = NewDiscordDispatcher(d.WebhookUrl)
		case "webhook":
			newDispatchers[d.Id] = NewWebhookDispatcher(d.WebhookUrl)
		case "telegram":
			newDispatchers[d.Id] = NewTelegramDispatcher(d.TelegramBotToken, d.TelegramChatId)
		}
	}
	m.dispatchers = newDispatchers
}

// HandleThreat processes a security threat and triggers alerts based on playbooks.
func HandleThreat(threat *telemetry.SecurityThreat) {
	if manager == nil {
		return
	}
	manager.process(threat)
}

func (m *AlertingManager) process(threat *telemetry.SecurityThreat) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil || !m.config.Enabled {
		return
	}

	// Smart autonomous mitigation: check aggregate IP risk score.
	//
	// Loopback is never shunned -- doing so would cut off the gateway's own
	// management traffic -- but it is deliberately only the *mitigation* that is
	// skipped. This used to `return` outright, which is upstream of the playbook
	// loop, so a threat from 127.0.0.1 was silently never reported either. That
	// is not a corner case: a gateway behind nginx, a Cloudflare tunnel or any
	// sidecar sees loopback as the source for every request until client-IP
	// extraction is configured, and in that deployment alerting reads as enabled
	// and configured while sending nothing at all.
	if threat.SourceIP != "" && m.ebpfManager != nil && !httputil.IsLoopback(threat.SourceIP) {
		score := telemetry.GetIPThreatScore(threat.SourceIP)
		// If score is high (e.g. > 150) or very high severity threat
		if score > 150 || threat.Severity == "critical" {
			// Ensure we don't re-mitigate if already mitigated or manually unmitigated
			if threat.ActionTaken == "" && !telemetry.IsIPUnmitigated(threat.SourceIP) {
				// To follow the "only block the attacker" policy, we prefer fingerprint-based
				// mitigation (already recorded in telemetry.RecordSecurityThreat).
				// We only perform kernel-level IP shunning for extremely severe threats
				// where the risk to infrastructure outweighs the potential for NAT false positives.
				if threat.Severity == "critical" && threat.JA4 == "" {
					if err := m.ebpfManager.ShunIP(threat.SourceIP); err == nil {
						threat.ActionTaken = "Autonomous Mitigation"
						telemetry.MarkIPMitigated(threat.SourceIP, "Autonomous mitigation (score > 150 or critical)")
						logger.L.LogInfo("autonomous smart mitigation: shunned high-risk IP",
							"ip", threat.SourceIP,
							"total_score", score,
							"threat_type", threat.Type,
							"severity", threat.Severity)
					}
				} else {
					logger.L.LogInfo("autonomous smart mitigation: skipping IP shun in favor of fingerprint mitigation",
						"ip", threat.SourceIP,
						"ja4", threat.JA4)
				}
			}
		}
	}

	for _, pb := range m.config.Playbooks {
		if m.matchPlaybook(pb, *threat) {
			m.executePlaybook(pb, *threat)
		}
	}
}

// matchPlaybook reports whether a playbook's trigger and threshold select the
// threat.
func (m *AlertingManager) matchPlaybook(pb *gateonv1.AlertPlaybook, threat telemetry.SecurityThreat) bool {
	if !triggerMatches(pb.EventType, threat) {
		return false
	}
	return threat.Score >= pb.Threshold
}

// triggerMatches maps a playbook trigger onto the detections it names.
//
// The dashboard stores its "Trigger Event" choices as camelCase ("wafThreat",
// "highAnomaly", "impossibleTravel", "authFailure"), the proto documents the
// same four as snake_case, and neither spelling is a value any detector puts
// in SecurityThreat.Type -- those are "waf_block", "brute_force_attempt" and
// so on. This used to compare the trigger to the type directly, with a
// "high_anomaly" special case that a second, unconditional comparison made
// unreachable, so every playbook except "All Threats" was configured,
// displayed, and silent.
func triggerMatches(trigger string, t telemetry.SecurityThreat) bool {
	switch normalizeTrigger(trigger) {
	case "", "all", "highanomaly":
		// A high anomaly is any detection whose score clears the threshold,
		// which matchPlaybook applies after this.
		return true
	case "wafthreat":
		return t.Category == "waf" || strings.HasPrefix(t.Type, "waf_")
	case "impossibletravel":
		return t.Type == "impossible_travel"
	case "authfailure":
		return t.Type == "brute_force_attempt" || t.Type == "auth_failure" ||
			t.Category == "brute_force" || t.Category == "auth"
	default:
		return normalizeTrigger(t.Type) == normalizeTrigger(trigger)
	}
}

// normalizeTrigger folds the camelCase and snake_case spellings of a trigger
// onto one form.
func normalizeTrigger(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "_", ""))
}

func (m *AlertingManager) executePlaybook(pb *gateonv1.AlertPlaybook, threat telemetry.SecurityThreat) {
	for _, dID := range pb.DispatcherIds {
		if d, ok := m.dispatchers[dID]; ok {
			go func(disp Dispatcher, t telemetry.SecurityThreat) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := disp.Send(ctx, t); err != nil {
					logger.L.LogError("failed to send alert", "dispatcher", dID, "error", err)
				}
			}(d, threat)
		}
	}

	// Handle actions like "block" (XDP shunning)
	if pb.Action == "block" && threat.SourceIP != "" && m.ebpfManager != nil {
		if err := m.ebpfManager.ShunIP(threat.SourceIP); err != nil {
			logger.L.LogError("playbook failed to shun IP", "ip", threat.SourceIP, "error", err)
		} else {
			logger.L.LogInfo("playbook automatically shunned IP", "ip", threat.SourceIP, "playbook", pb.Name)
		}
	}
}
