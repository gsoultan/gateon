// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package alerting

import (
	"testing"
	"time"

	"github.com/gsoultan/gateon/internal/audit"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// withManager installs m as the package manager AuditSink reads, for one test.
func withManager(t *testing.T, m *AlertingManager) {
	t.Helper()
	prev := manager
	manager = m
	t.Cleanup(func() { manager = prev })
}

// A takeover sent no alert: alerting watched attack traffic only, and the
// entries that mean control changed hands went to an audit log in the
// database the attacker now holds (ADR 0099).
func TestAdministratorActivityAlerts(t *testing.T) {
	cases := []struct {
		entry    audit.AuditEntry
		severity string
	}{
		{audit.AuditEntry{Action: "login_new_source", Resource: "auth"}, "high"},
		{audit.AuditEntry{Action: "update", Resource: "user"}, "high"},
		{audit.AuditEntry{Action: "delete", Resource: "user"}, "high"},
		{audit.AuditEntry{Action: "reset_2fa", Resource: "user"}, "high"},
		{audit.AuditEntry{Action: "update", Resource: "audit_config"}, "critical"},
		{audit.AuditEntry{Action: "update", Resource: "alerting_config"}, "critical"},
		{audit.AuditEntry{Action: "verify_failed", Resource: "audit_chain"}, "critical"},
		{audit.AuditEntry{Action: "update", Resource: "waf_config", Details: "Changing WAF settings: paranoia 2 -> 1"}, "high"},
		{audit.AuditEntry{Action: "update", Resource: "waf_config", Details: "Changing WAF settings: enabled true -> false"}, "critical"},
		{audit.AuditEntry{Action: "update", Resource: "waf_config", Details: "Changing WAF settings: audit only false -> true"}, "critical"},
		{audit.AuditEntry{Action: "upload", Resource: "certificate"}, "high"},
		{audit.AuditEntry{Action: "delete", Resource: "waf_rule"}, "medium"},
	}
	for _, c := range cases {
		m, rec := newTestManager(nil)
		m.config.Playbooks = nil // no playbook: the alert must not need one
		withManager(t, m)
		c.entry.UserID, c.entry.IPAddress, c.entry.Timestamp = "mallory", "203.0.113.9", time.Now()
		AuditSink(c.entry)
		if !rec.waitForCount(t, 1) {
			t.Errorf("%s/%s: no alert sent", c.entry.Action, c.entry.Resource)
			continue
		}
		got := rec.sent[0]
		if got.Category != CategoryAdmin || got.Severity != c.severity || got.SourceIP != "203.0.113.9" {
			t.Errorf("%s/%s: alert = %+v, want category admin, severity %s", c.entry.Action, c.entry.Resource, got, c.severity)
		}
	}
}

// Ordinary management work and the gateway's own entries stay quiet; an
// alert on every route save is an alert nobody reads.
func TestRoutineEntriesDoNotAlert(t *testing.T) {
	for _, e := range []audit.AuditEntry{
		{UserID: "admin", Action: "update", Resource: "route"},
		{UserID: "admin", Action: "update", Resource: "global_config"},
		{UserID: "admin", Action: "login_success", Resource: "auth"},
		{UserID: "system", Action: "waf_block", Resource: "/login"},
	} {
		if _, ok := adminSeverity(e); ok {
			t.Errorf("%s/%s alerts", e.Action, e.Resource)
		}
	}
}

// An administrator-activity alert never blocks its source, whatever a
// playbook says: that address is an administrator's.
func TestAdministratorActivityNeverBlocksItsSource(t *testing.T) {
	em := &stubEbpf{}
	m, rec := newTestManager(em)
	m.config.Playbooks[0].Action = "block"
	withManager(t, m)
	AuditSink(audit.AuditEntry{UserID: "admin", Action: "update", Resource: "user", IPAddress: "198.51.100.4"})
	if !rec.waitForCount(t, 1) {
		t.Fatal("no alert sent")
	}
	if len(em.shunned) != 0 {
		t.Fatalf("the administrator's address was shunned: %v", em.shunned)
	}
}

func TestAdministratorActivityIsQuietWhenAlertingIsOff(t *testing.T) {
	m, rec := newTestManager(nil)
	m.config = &gateonv1.AlertingConfig{Enabled: false}
	withManager(t, m)
	AuditSink(audit.AuditEntry{Action: "update", Resource: "user"})
	if rec.waitForCount(t, 1) {
		t.Fatal("an alert was sent with alerting off")
	}
}

// Switching alerting off is itself announced, to the destinations it is
// switched off for: the entry is written before the change applies, and its
// alert is bound to the destinations in force then.
func TestSwitchingAlertingOffIsSentToTheOldDestinations(t *testing.T) {
	m, rec := newTestManager(nil)
	withManager(t, m)
	AuditSink(audit.AuditEntry{UserID: "mallory", Action: "update", Resource: "alerting_config",
		Details: "Changing alerting: enabled false, 0 destinations, 0 playbooks"})
	m.mu.Lock()
	m.config = &gateonv1.AlertingConfig{Enabled: false}
	m.dispatchers = map[string]Dispatcher{}
	m.mu.Unlock()
	if !rec.waitForCount(t, 1) {
		t.Fatal("switching alerting off sent nothing to the destinations it removed")
	}
}
