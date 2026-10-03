// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gsoultan/gateon/internal/auth"
	"github.com/gsoultan/gateon/internal/security/correlation"
	"github.com/gsoultan/gateon/internal/security/fim"
	"github.com/gsoultan/gateon/internal/security/posture"
	"github.com/gsoultan/gateon/internal/security/siem"
)

// SecurityPostureProvider produces the current security posture report. It is
// supplied by the server wiring (which holds the subsystem managers) so the
// handler package stays decoupled from those concrete managers.
type SecurityPostureProvider func(context.Context) *SecurityPostureReport

// SecurityPostureReport is the JSON payload returned by GET /v1/security/posture.
// It summarizes the freshness and health of Gateon's defensive subsystems so
// operators (and external SIEMs) can assess detection coverage at a glance.
type SecurityPostureReport struct {
	Version     string            `json:"version"`
	GeneratedAt time.Time         `json:"generatedAt"`
	WAF         WAFPosture        `json:"waf"`
	ClamAV      ClamAVPosture     `json:"clamav"`
	Signatures  SignaturePosture  `json:"signatures"`
	SIEM        siem.StatusReport `json:"siem"`
	FIM         *fim.Status       `json:"fim,omitzero"`
	Ebpf        EbpfPosture       `json:"ebpf"`
	// Score is the posture percentage and the controls behind it, computed
	// from configuration only (ADR 0048).
	Score posture.Score `json:"score"`
}

// SignaturePosture reports the YARA-lite upload signature engine as the routes
// run it. It scans only inside a file_security middleware with
// enable_signature_scan on, so Enabled means at least one enabled route does,
// Routes says how many, and RuleCount is the built-in rule set's size then.
type SignaturePosture struct {
	Enabled   bool `json:"enabled"`
	Routes    int  `json:"routes"`
	RuleCount int  `json:"ruleCount"`
}

// WAFPosture reports what the WAF does. Mode is the gateway-wide WAF's
// effective mode ("enforce", "detect" for audit-only, "off"); Routes counts
// the enabled HTTP routes by the mode of the WAF that actually inspects each,
// which for a route with its own WAF middleware is that middleware's.
//
// There is no autoUpdate: rules are compiled in and nothing downloads them.
// CustomRulesFromDisk is what the repurposed auto_update_rules flag does --
// load a rules directory already present under the data directory.
type WAFPosture struct {
	Enabled bool `json:"enabled"`
	// Mode is what the gateway-wide WAF does with a match: "enforce",
	// "detect" (audit only: it blocks nothing) or "off". Enabled alone
	// reported an audit-only WAF as protecting (truth T12, ADRs 0044, 0048).
	Mode                string                `json:"mode"`
	Routes              posture.RouteCoverage `json:"routes"`
	CustomRulesFromDisk bool                  `json:"customRulesFromDisk"`
	LastUpdated         time.Time             `json:"lastUpdated,omitzero"`
}

// ClamAVPosture reports antivirus engine availability and scan freshness.
type ClamAVPosture struct {
	Enabled    bool      `json:"enabled"`
	Installed  bool      `json:"installed"`
	LastScan   time.Time `json:"lastScan,omitzero"`
	LastResult string    `json:"lastResult,omitzero"`
	LastError  string    `json:"lastError,omitzero"`
}

// EbpfPosture reports eBPF offloading and security state.
type EbpfPosture struct {
	Enabled    bool   `json:"enabled"`
	Attached   bool   `json:"attached"`
	Interface  string `json:"interface,omitzero"`
	AttachMode string `json:"attachMode,omitzero"`
	ShunnedIPs int    `json:"shunnedIps"`
}

// registerSecurityHandlers wires the security posture and correlated-incidents
// endpoints.
func registerSecurityHandlers(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /v1/security/posture", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		report := d.buildPostureReport(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(report)
	})

	// Correlated incidents are higher-level findings raised by the correlation
	// engine when multiple related detections from one source cross a threshold,
	// annotated with MITRE ATT&CK techniques. They are retained in-process so the
	// Security Hub can surface them without an external SIEM.
	mux.HandleFunc("GET /v1/security/incidents", func(w http.ResponseWriter, r *http.Request) {
		if !RequirePermission(w, r, auth.ActionRead, auth.ResourceDiagnostics) {
			return
		}
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}
		incidents := correlation.DefaultIncidentStore.List(limit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"incidents":   incidents,
			"totalSeen":   correlation.DefaultIncidentStore.TotalSeen(),
			"retained":    correlation.DefaultIncidentStore.Len(),
			"generatedAt": time.Now(),
		})
	})
}

// buildPostureReport returns the posture from the configured provider, falling
// back to a minimal report (version + timestamp) when no provider is wired so
// the endpoint never 500s on a partially-initialized server.
func (d *Deps) buildPostureReport(ctx context.Context) *SecurityPostureReport {
	if d.SecurityPosture != nil {
		if report := d.SecurityPosture(ctx); report != nil {
			return report
		}
	}
	return &SecurityPostureReport{Version: d.Version, GeneratedAt: time.Now()}
}
