// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"strings"

	"github.com/gsoultan/gateon/internal/audit"
	"github.com/gsoultan/gateon/internal/telemetry"
)

// CategoryAdmin is the category of an alert on administrator activity.
const CategoryAdmin = "admin"

// adminRecommendation ends every alert on administrator activity.
const adminRecommendation = "If nobody on your team did this, treat the gateway as taken over: " +
	"see doc/incident-compromise.md."

// adminRule says how loud an audit entry's alert is.
type adminRule struct {
	action, resource string // "" matches any
	severity         string
}

// adminRules are the audit entries that alert, first match wins (ADR 0097).
//
// Alerting covered attack traffic and nothing else, so a takeover was silent:
// a new administrator, a reset second factor, the WAF switched off and the
// audit log tampered with all went to the audit log, which is in the database
// the attacker now controls and which nobody reads until they already
// suspect something. These are the entries that mean control of the gateway
// changed hands or its protection went down.
var adminRules = []adminRule{
	{action: "verify_failed", resource: "audit_chain", severity: "critical"},
	{resource: "audit_config", severity: "critical"},
	{action: "update", resource: "alerting_config", severity: "critical"},
	{action: "update", resource: "waf_config", severity: "high"},
	{action: "login_new_source", resource: "auth", severity: "high"},
	{action: "setup", resource: "system", severity: "high"},
	{resource: "user", severity: "high"},
	{resource: "certificate", severity: "high"},
	{resource: "clamav", severity: "high"},
	{resource: "waf_rule", severity: "warning"},
	{action: "create", resource: "api_token", severity: "warning"},
	{action: "install_update", resource: "global", severity: "warning"},
}

// adminSeverity is entry's alert severity, and whether it alerts at all. A
// WAF change that switches protection off or to recording only is critical.
func adminSeverity(e audit.AuditEntry) (string, bool) {
	for _, r := range adminRules {
		if (r.action == "" || r.action == e.Action) && (r.resource == "" || r.resource == e.Resource) {
			if e.Resource == "waf_config" && (strings.Contains(e.Details, "enabled true -> false") ||
				strings.Contains(e.Details, "audit only false -> true")) {
				return "critical", true
			}
			return r.severity, true
		}
	}
	return "", false
}

// AuditSink is the audit.Sink that turns administrator activity into alerts.
// It runs on the goroutine that stored the entry and never blocks: delivery
// is dispatch's, bounded like every other alert.
func AuditSink(e audit.AuditEntry) {
	m := manager
	if m == nil {
		return
	}
	severity, ok := adminSeverity(e)
	if !ok {
		return
	}
	m.processAdmin(adminThreat(e, severity))
}

// adminThreat is the alert for e, in the shape every dispatcher sends.
func adminThreat(e audit.AuditEntry, severity string) telemetry.SecurityThreat {
	return telemetry.SecurityThreat{
		ID:             e.ID,
		Type:           "admin_" + e.Action + "_" + e.Resource,
		Category:       CategoryAdmin,
		Severity:       severity,
		SourceIP:       e.IPAddress,
		Details:        e.UserID + ": " + e.Details,
		Time:           e.Timestamp,
		Recommendation: adminRecommendation,
	}
}

// processAdmin sends an administrator-activity alert to every destination.
//
// Not through the playbooks: a playbook is how an operator picks which
// attacks are worth a message, and a takeover alert that waits for someone to
// have written a playbook for it is the silence this exists to end. And never
// a block: the source is an administrator's address, and shunning it is the
// attacker's outcome, not the defender's.
func (m *AlertingManager) processAdmin(threat telemetry.SecurityThreat) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.config == nil || !m.config.Enabled {
		return
	}
	for id, d := range m.dispatchers {
		m.dispatch(id, d, threat)
	}
}
